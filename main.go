package main

import (
    "net/http"
    "html/template"
    "log"
)

func renderTemplate(w http.ResponseWriter, tmpl string) {
    t, _ := template.ParseFiles("templates/" + tmpl + ".html")
    t.Execute(w, nil)
}

func main() {
    fs := http.FileServer(http.Dir("assets"))
    http.Handle("/assets/", http.StripPrefix("/assets/", fs))

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "index")
    })

    http.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
        renderTemplate(w, "dashboard")
    })

    log.Println("🔥 HiddenDoor portal is running on http://localhost:1337")
    http.ListenAndServe(":1337", nil)
}
