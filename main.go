package main

import (
    "fmt"
    "html/template"
    "log"
    "net/http"
    "os/exec"
    "strings"
	"encoding/base64"
	"golang.org/x/crypto/argon2"
    "github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte("trhacknon-ultra-secret-key"))

var allowedCommands = []string{
    "id", "whoami", "hostname", "uname", "uname -a",
}

// Simulé (tu pourras remplacer par Argon2 plus tard)
var passwordHash = "trhacknon"

const storedHash = "7BmFwU6ohzjnsotDgiS8i9mWC6De68K6vl90mec3H6Y"

func hashPassword(password string) string {
	salt := []byte("saltsaltsalt") // Utiliser un salt sécurisé et stocké séparément en prod
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return base64.RawStdEncoding.EncodeToString(hash)
}

func verifyPassword(password string) bool {
	return hashPassword(password) == storedHash
}


func execCommand(cmd string) string {
    for _, allowed := range allowedCommands {
        if strings.TrimSpace(cmd) == allowed {
            out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
            if err != nil {
                return fmt.Sprintf("Erreur: %s", err.Error())
            }
            return string(out)
        }
    }
    return "⛔ Commande non autorisée."
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "hiddendoor-session")
    if session.Values["user"] != nil {
        http.Redirect(w, r, "/dashboard", http.StatusFound)
        return
    }

    if r.Method == http.MethodPost {
        r.ParseForm()
        password := r.FormValue("password")
        if verifyPassword(password) {
            session.Values["user"] = "trhacknon"
            session.Save(r, w)
            http.Redirect(w, r, "/dashboard", http.StatusFound)
            return
        }
    }

    renderTemplate(w, "login", nil)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "hiddendoor-session")
    if session.Values["user"] == nil {
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }

    output := "🔐 Prêt à recevoir des commandes autorisées..."
    if r.Method == http.MethodPost {
        r.ParseForm()
        cmd := r.FormValue("cmd")
        output = execCommand(cmd)
    }

    renderTemplate(w, "dashboard", map[string]string{
        "Output": output,
    })
}

func renderTemplate(w http.ResponseWriter, tmpl string, data any) {
    t, _ := template.ParseFiles("templates/" + tmpl + ".html")
    t.Execute(w, data)
}

func main() {
    http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
    http.HandleFunc("/", loginHandler)
    http.HandleFunc("/dashboard", dashboardHandler)

    fmt.Println("🧠 HiddenDoor: http://localhost:9000")
    log.Fatal(http.ListenAndServe(":9000", nil))
}
