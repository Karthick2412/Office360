package main

import (
	"fmt"
	"log"
	"net/http"
	"taskupdate/controllers"
	"taskupdate/initializers"
	"taskupdate/middleware"

	"github.com/rs/cors"

	"github.com/gorilla/mux"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.SyncDatabase()
	//DB:=initializers.ConnectToDb()
}
func main() {

	fmt.Println("Hi hello")
	//initialMigratraion()
	initialRouterr()

}
func initialRouterr() {
	rout := mux.NewRouter().StrictSlash(true)
	rout.Use(middleware.CommonMiddleware)
	//allowedHeaders := "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Access-Control-Request-Headers, Access-Control-Request-Method, Connection, Host, Origin, User-Agent, Referer, Cache-Control, X-header"

	// rout.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	w.Header().Set("Content-Type", "application/json")
	// 	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	// 	w.Header().Set("Access-Control-Allow-Headers:", "*")
	// 	w.Header().Set("Access-Control-Allow-Origin", "*")
	// 	//w.Header().Set("Access-Control-Expose-Headers", "Authorization")
	// 	//w.Write([]byte("{\"hello\": \"world\"}"))
	// })
	// c := cors.New(cors.Options{
	// 	AllowedOrigins:   []string{"foo.com"},
	// 	AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete},
	// 	AllowCredentials: true,
	// })
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete},
		AllowCredentials: true,
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"*"},
	})
	handler2 := c.Handler(rout)
	//handler := cors.Default().Handler(rout)
	rout.HandleFunc("/login", controllers.Login).Methods("POST")
	rout.HandleFunc("/userCreate", controllers.Signup).Methods("POST")
	rout.HandleFunc("/forgotpassword", controllers.ForgotPassword).Methods("POST")
	rout.HandleFunc("/resetpassword", controllers.ResetPassword).Methods("POST")
	rout.HandleFunc("/profileupdate", controllers.ProfileSetting).Methods("GET")
	auth := rout.NewRoute().Subrouter()
	auth.Use(middleware.JwtVerify)

	auth.HandleFunc("/dailyTask", controllers.DailyTask).Methods("POST")
	auth.HandleFunc("/task", controllers.GetTasks).Methods("GET")
	auth.HandleFunc("/report/{StDate}/{EndDate}", controllers.Report).Methods("GET")
	auth.HandleFunc("/validate", controllers.Validate).Methods("GET")
	//r.Use(middleware.CommonMiddleware)192.168.109.189  192.168.29.221 185.27.134.11:21
	log.Fatal(http.ListenAndServe("192.168.29.221:8080", handler2))
}
