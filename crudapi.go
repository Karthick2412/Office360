package main

import (
	"log"
	"net/http"
	"taskupdate/controllers"
	"taskupdate/middleware"

	"github.com/rs/cors"

	"github.com/gorilla/mux"
)

func initialRouter() {
	rout := mux.NewRouter().StrictSlash(true)

	//http.ListenAndServe(":8080", handler)
	rout.Use(middleware.CommonMiddleware)
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
	//r.Use(middleware.CommonMiddleware)192.168.109.189
	handler := cors.Default().Handler(rout)
	log.Fatal(http.ListenAndServe("192.168.109.189:8080", handler))
}
