package auth.go

import (
	"math/rand"
	"net/http"
	"time"
)

// IUserDB IUserDB
type IUserDB interface {
	IsEqualPassword(password string) bool
}

// IDB  DB interface
type IDB interface {
	Auth(user string) (IUserDB, error)
}

// IData IData
type IData interface {
	ToBytes() []byte
}

// IApp App interface
type IApp interface {
	IsError(err error) bool
	GetToken(IUserDB) (IData, error)
}

// ErrUserPass Err User or Pass
var ErrUserPass = []byte("error user or password")

var min = 100
var max = 500

// Auther auth handle
func Auther(app IApp, db IDB) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PostForm.Get("username")
		password := r.PostForm.Get("password")
		User, err := db.Auth(username)
		if app.IsError(err) &&
			!User.IsEqualPassword(password) {
			sleeping := time.Duration(rand.Intn(max-min)+min) / 100 * time.Second
			time.Sleep(sleeping)
			w.WriteHeader(401)
			w.Write(ErrUserPass)
			return
		}
		token, err := app.GetToken(User)
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
		}
		w.Write(token.ToBytes())
	}
}
