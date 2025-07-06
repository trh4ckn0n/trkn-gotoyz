package main

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "html/template"
    "log"
    "net/http"
    "os"
    "os/exec"
    "strings"
    "time"

    "github.com/gorilla/sessions"
    "golang.org/x/crypto/argon2"
)

// ----- Configuration -----
var (
    store           = sessions.NewCookieStore([]byte("trhacknon-ultra-secret-key"))
    salt            = generateSalt()
    storedPassword  = "trhacknon"
    storedHash      = hashPassword(storedPassword, salt)
    allowedCommands = []string{"id", "whoami", "hostname", "uname", "uname -a"}
)

// ----- Utilities -----
func generateSalt() []byte {
    s := make([]byte, 16)
    _, err := rand.Read(s)
    if err != nil {
        panic(err)
    }
    return s
}

func hashPassword(password string, salt []byte) string {
    hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
    return base64.RawStdEncoding.EncodeToString(hash)
}

func verifyPassword(password string) bool {
    return hashPassword(password, salt) == storedHash
}

func execCommand(cmd string) string {
    for _, allowed := range allowedCommands {
        if strings.TrimSpace(cmd) == allowed {
            out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
            if err != nil {
                return fmt.Sprintf("❌ Erreur: %s", err.Error())
            }
            return string(out)
        }
    }
    return "⛔ Commande non autorisée."
}

func systemInfo() string {
    out, _ := exec.Command("uname", "-a").CombinedOutput()
    return string(out)
}

// ----- Handlers -----
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
            session.Options = &sessions.Options{
                Path:     "/",
                MaxAge:   3600,
                HttpOnly: true,
            }
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

    hostname, _ := os.Hostname()
    now := time.Now().Format("02/01/2006 15:04:05")

    data := map[string]interface{}{
        "Output":   output,
        "User":     session.Values["user"],
        "SysInfo":  systemInfo(),
        "Hostname": hostname,
        "Time":     now,
    }

    renderTemplate(w, "dashboard", data)
}

// ----- Template Rendering -----
func renderTemplate(w http.ResponseWriter, tmpl string, data any) {
    t, err := template.ParseFiles("templates/" + tmpl + ".html")
    if err != nil {
        http.Error(w, "Template error: "+err.Error(), 500)
        return
    }
    t.Execute(w, data)
}

// ----- Main Entry -----
func main() {
    http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))
    http.HandleFunc("/", loginHandler)
    http.HandleFunc("/dashboard", dashboardHandler)

    fmt.Println("🧠 HiddenDoor démarré: http://localhost:9000")
    log.Fatal(http.ListenAndServe(":9000", nil))
}
