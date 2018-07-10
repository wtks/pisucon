package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
	"crypto/sha512"
	"golang.org/x/sync/singleflight"
	"github.com/quasoft/memstore"
)

var (
	db    *sqlx.DB
	store *memstore.MemStore

	group singleflight.Group

	usernameRegexp = regexp.MustCompile("\\A[0-9a-zA-Z_]{3,}\\z")
	passwordRegexp = regexp.MustCompile("\\A[0-9a-zA-Z_]{6,}\\z")

	fmap = template.FuncMap{"imageURL": func(p Post) string {
		ext := ""
		switch p.Mime {
		case "image/jpeg":
			ext = ".jpg"
		case "image/png":
			ext = ".png"
		case "image/gif":
			ext = ".gif"
		}

		return "/image/" + strconv.Itoa(p.ID) + ext
	},
	}
	loginTmpl    = template.Must(template.ParseFiles(getTemplPath("layout.html"), getTemplPath("login.html")))
	registerTmpl = template.Must(template.ParseFiles(getTemplPath("layout.html"), getTemplPath("register.html")))
	bannedTmpl   = template.Must(template.ParseFiles(getTemplPath("layout.html"), getTemplPath("banned.html")))
	postTmpl     = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(getTemplPath("layout.html"), getTemplPath("post_id.html"), getTemplPath("post.html")))
	postsTmpl    = template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(getTemplPath("posts.html"), getTemplPath("post.html")))
	indexTmpl    = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(getTemplPath("layout.html"), getTemplPath("index.html"), getTemplPath("posts.html"), getTemplPath("post.html")))
	userTmpl     = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(getTemplPath("layout.html"), getTemplPath("user.html"), getTemplPath("posts.html"), getTemplPath("post.html")))
)

const (
	ISO8601_FORMAT = "2006-01-02T15:04:05-07:00"
	UploadLimit    = 10 * 1024 * 1024 // 10mb

	// CSRF Token error
	StatusUnprocessableEntity = 422

	getPostsQuery = "SELECT posts.id AS id, posts.body AS body, posts.mime As mime, posts.created_at AS created_at, users.account_name AS `u.account_name` FROM posts INNER JOIN users ON posts.user_id = users.id AND users.del_flg = 0"
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []*Comment
	User         User      `db:"u"`
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User      `db:"u"`
}

func init() {
	store = memstore.NewMemStore([]byte("sendagaya"))
}

func digest(src string) string {
	sum512 := sha512.Sum512([]byte(src))
	return hex.EncodeToString(sum512[:])
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + digest(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")
	return session
}

func getSessionUser(s *sessions.Session) *User {
	uid, ok := s.Values["user_id"]
	if !ok || uid == nil {
		return nil
	}

	u := &User{}
	if db.Get(u, "SELECT * FROM `users` WHERE `id` = ? LIMIT 1", uid) != nil {
		return nil
	}
	return u
}

func getFlash(s *sessions.Session, w http.ResponseWriter, r *http.Request, key string) string {
	value, ok := s.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(s.Values, key)
		s.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []*Post, CSRFToken string, allComments bool) error {
	for _, p := range results {
		query := "SELECT comments.id AS id, comments.comment AS `comment`, comments.created_at AS created_at, users.account_name AS `u.account_name` FROM `comments` INNER JOIN `users` ON `users`.`id` = `comments`.`user_id` AND `comments`.`post_id` = ? ORDER BY `comments`.`created_at`"
		if !allComments {
			query += " LIMIT 3"
		}

		cerr := db.Select(&p.Comments, query, p.ID)
		if cerr != nil {
			return cerr
		}

		if allComments {
			p.CommentCount = len(p.Comments)
		} else {
			err := db.Get(&p.CommentCount, "SELECT COUNT(*) AS `count` FROM `comments` WHERE `post_id` = ?", p.ID)
			if err != nil {
				return err
			}
		}

		p.CSRFToken = CSRFToken
	}

	return nil
}

func getCSRFToken(s *sessions.Session) string {
	csrfToken, ok := s.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := io.ReadFull(crand.Reader, k); err != nil {
		panic("error reading from random source: " + err.Error())
	}
	return hex.EncodeToString(k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func GetInitialize(w http.ResponseWriter, r *http.Request) {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}

	w.WriteHeader(http.StatusOK)
}

func GetLogin(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	me := getSessionUser(s)
	if me != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	loginTmpl.Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(s, w, r, "notice")})
}

func PostLogin(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	if getSessionUser(s) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")
	u := &User{}
	db.Get(u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0 LIMIT 1", accountName)

	if calculatePasshash(u.AccountName, password) != u.Passhash {
		s.Values["notice"] = "アカウント名かパスワードが間違っています"
		s.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	s.Values["user_id"] = u.ID
	s.Values["csrf_token"] = secureRandomStr(16)
	s.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func GetRegister(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	if getSessionUser(s) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	registerTmpl.Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(s, w, r, "notice")})
}

func PostRegister(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	if getSessionUser(s) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")
	if !(usernameRegexp.MatchString(accountName) && passwordRegexp.MatchString(password)) {
		s.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		s.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ? LIMIT 1", accountName)

	if exists == 1 {
		s.Values["notice"] = "アカウント名がすでに使われています"
		s.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	result, eerr := db.Exec("INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)", accountName, calculatePasshash(accountName, password))
	if eerr != nil {
		fmt.Println(eerr.Error())
		return
	}

	uid, lerr := result.LastInsertId()
	if lerr != nil {
		fmt.Println(lerr.Error())
		return
	}
	s.Values["user_id"] = uid
	s.Values["csrf_token"] = secureRandomStr(16)
	s.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func GetLogout(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	delete(s.Values, "user_id")
	s.Options = &sessions.Options{MaxAge: -1}
	s.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func GetIndex(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	me := getSessionUser(s)
	if me == nil {
		me = &User{}
	}

	token := getCSRFToken(s)

	v, err, _ := group.Do("index", func() (interface{}, error) {
		var posts []*Post
		if err := db.Select(&posts, getPostsQuery+" ORDER BY posts.created_at DESC LIMIT 20"); err != nil {
			return nil, err
		}
		if err := makePosts(posts, "", false); err != nil {
			return nil, err
		}
		return posts, nil
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	posts := make([]*Post, len(v.([]*Post)))
	for i, v := range v.([]*Post) {
		p := *v
		p.CSRFToken = token
		posts[i] =  &p
	}

	indexTmpl.Execute(w, struct {
		Posts     []*Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, *me, token, getFlash(s, w, r, "notice")})
}

func GetAccountName(c web.C, w http.ResponseWriter, r *http.Request) {
	user := &User{}
	if err := db.Get(user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0 LIMIT 1", c.URLParams["accountName"]); err != nil {
		fmt.Println(err)
		return
	}
	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var results []*Post
	db.Select(&results, getPostsQuery+" WHERE posts.user_id = ? ORDER BY posts.created_at DESC LIMIT 20", user.ID)
	s := getSession(r)
	if err := makePosts(results, getCSRFToken(s), false); err != nil {
		fmt.Println(err)
		return
	}

	commentCount := 0
	db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)

	var postIDs []int
	db.Select(&postIDs, "SELECT `id` FROM `posts` WHERE `user_id` = ?", user.ID)
	postCount := len(postIDs)

	commentedCount := 0
	if postCount > 0 {
		var s []string
		for range postIDs {
			s = append(s, "?")
		}
		placeholder := strings.Join(s, ", ")

		// convert []int -> []interface{}
		args := make([]interface{}, len(postIDs))
		for i, v := range postIDs {
			args[i] = v
		}

		if err := db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `post_id` IN ("+placeholder+")", args...); err != nil {
			fmt.Println(err)
			return
		}
	}

	me := getSessionUser(s)
	if me == nil {
		me = &User{}
	}
	userTmpl.Execute(w, struct {
		Posts          []*Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{results, *user, postCount, commentCount, commentedCount, *me})
}

func GetPosts(w http.ResponseWriter, r *http.Request) {
	m, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(parseErr)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}
	t, terr := time.Parse(ISO8601_FORMAT, maxCreatedAt)
	if terr != nil {
		fmt.Println(terr)
		return
	}

	var posts []*Post
	if db.Select(&posts, getPostsQuery+" WHERE posts.created_at <= ? ORDER BY posts.created_at DESC LIMIT 20", t.Format(ISO8601_FORMAT)) != nil {
		return
	}
	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if err := makePosts(posts, getCSRFToken(getSession(r)), false); err != nil {
		fmt.Println(err)
		return
	}

	postsTmpl.Execute(w, posts)
}

func GetPostsID(c web.C, w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(c.URLParams["id"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var posts []*Post
	if db.Select(&posts, getPostsQuery+" WHERE posts.id = ? LIMIT 1", pid) != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	s := getSession(r)
	if err := makePosts(posts, getCSRFToken(s), true); err != nil {
		fmt.Println(err)
		return
	}

	user := getSessionUser(s)
	if user == nil {
		user = &User{}
	}
	postTmpl.Execute(w, struct {
		Post *Post
		Me   User
	}{posts[0], *user})
}

func PostIndex(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	me := getSessionUser(s)
	if me == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if r.FormValue("csrf_token") != getCSRFToken(s) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	file, header, ferr := r.FormFile("file")
	if ferr != nil {
		s.Values["notice"] = "画像が必須です"
		s.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := header.Header["Content-Type"][0]
	ext := ""
	switch {
	case strings.HasSuffix(mime, "jpeg"):
		ext = "jpg"
		break
	case strings.HasSuffix(mime, "png"):
		ext = "png"
		break
	case strings.HasSuffix(mime, "gif"):
		ext = "gif"
		break
	default:
		s.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
		s.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	filedata, rerr := ioutil.ReadAll(file)
	if rerr != nil {
		fmt.Println(rerr.Error())
	}

	if len(filedata) > UploadLimit {
		s.Values["notice"] = "ファイルサイズが大きすぎます"
		s.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	result, eerr := db.Exec("INSERT INTO `posts` (`user_id`, `mime`, `body`) VALUES (?,?,?)", me.ID, mime, r.FormValue("body"))
	if eerr != nil {
		fmt.Println(eerr.Error())
		return
	}

	pid, lerr := result.LastInsertId()
	if lerr != nil {
		fmt.Println(lerr.Error())
		return
	}

	if err := ioutil.WriteFile(fmt.Sprintf("../public/image/%d.%s", pid, ext), filedata, os.ModePerm); err != nil {
		panic(err)
	}

	group.Forget("index")
	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
	return
}

func GetImage(c web.C, w http.ResponseWriter, r *http.Request) {
	pidStr := c.URLParams["id"]
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	post := Post{}
	derr := db.Get(&post, "SELECT * FROM `posts` WHERE `id` = ?", pid)
	if derr != nil {
		fmt.Println(derr.Error())
		return
	}

	ext := c.URLParams["ext"]

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		ioutil.WriteFile(fmt.Sprintf("../public/image/%d.%s", post.ID, ext), post.Imgdata, os.ModePerm)
		w.Header().Set("Content-Type", post.Mime)
		w.Header().Set("Cache-Control", "max-age=31536000, public")
		_, err := w.Write(post.Imgdata)
		if err != nil {
			fmt.Println(err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func PostComment(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	me := getSessionUser(s)
	if me == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(s) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	postID, ierr := strconv.Atoi(r.FormValue("post_id"))
	if ierr != nil {
		fmt.Println("post_idは整数のみです")
		return
	}

	db.Exec("INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)", postID, me.ID, r.FormValue("comment"))

	group.Forget("index")
	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func GetAdminBanned(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	me := getSessionUser(s)
	if me == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	var users []*User
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		fmt.Println(err)
		return
	}

	bannedTmpl.Execute(w, struct {
		Users     []*User
		Me        User
		CSRFToken string
	}{users, *me, getCSRFToken(s)})
}

func PostAdminBanned(w http.ResponseWriter, r *http.Request) {
	s := getSession(r)
	me := getSessionUser(s)
	if me == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(s) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	r.ParseForm()
	q, vs, err := sqlx.In("UPDATE `users` SET `del_flg` = 1 WHERE `id` IN (?)", r.Form["uid[]"])
	if err != nil {
		panic(err)
	}

	db.Exec(q, vs...)

	group.Forget("index")
	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@unix(/var/run/mysqld/mysqld.sock)/%s?charset=utf8mb4&parseTime=true&loc=Local",
		user,
		password,
		dbname,
	)

	var err error
	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	goji.Get("/initialize", GetInitialize)
	goji.Get("/login", GetLogin)
	goji.Post("/login", PostLogin)
	goji.Get("/register", GetRegister)
	goji.Post("/register", PostRegister)
	goji.Get("/logout", GetLogout)
	goji.Get("/", GetIndex)
	goji.Get(regexp.MustCompile(`^/@(?P<accountName>[a-zA-Z]+)$`), GetAccountName)
	goji.Get("/posts", GetPosts)
	goji.Get("/posts/:id", GetPostsID)
	goji.Post("/", PostIndex)
	goji.Get("/image/:id.:ext", GetImage)
	goji.Post("/comment", PostComment)
	goji.Get("/admin/banned", GetAdminBanned)
	goji.Post("/admin/banned", PostAdminBanned)
	//goji.Get("/*", http.FileServer(http.Dir("../public"))) //nginxに任せる
	goji.Serve()
}
