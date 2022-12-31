package middleware

import (
	"context"
	"fmt"
	"net/http"
	"taskupdate/initializers"
	"taskupdate/models"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func CommonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Access-Control-Request-Headers, Access-Control-Request-Method, Connection, Host, Origin, User-Agent, Referer, Cache-Control, X-header")
		next.ServeHTTP(w, r)
	})
}
func JwtVerify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//func RequireAuth(w http.ResponseWriter, r *http.Request) {
		//tokenString, err := r.Cookie("Authorization")
		tokenString := r.Header.Get("tok")
		if tokenString == "" {
			http.Error(w, "token not found", http.StatusBadRequest)
			return
		}
		// if err != nil {
		// 	switch {
		// 	case errors.Is(err, http.ErrNoCookie):
		// 		http.Error(w, "cookie not found", http.StatusBadRequest)
		// 	default:
		// 		log.Println(err)
		// 		http.Error(w, "server error", http.StatusInternalServerError)
		// 	}
		// 	return
		// }

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			secret := "djaxcompany"
			return []byte(secret), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			//check the token expiration
			if float64(time.Now().Unix()) > claims["exp"].(float64) {
				http.Error(w, "server error", http.StatusUnauthorized)
			}

			//check is user available with that sub
			var usRef models.User
			initializers.ConnectToDb().Where("id = ?", claims["sub"]).First(&usRef)
			//initializers.ConnectToDb().First(&usRef, claims["sub"])

			if usRef.Id == "" {
				http.Error(w, "server error", http.StatusUnauthorized)
			}
			ctx := context.WithValue(r.Context(), "user", usRef)
			next.ServeHTTP(w, r.WithContext(ctx))
			//fmt.Println(claims["sub"], claims["exp"])
		} else {
			fmt.Println(err)
		}

	})

}
