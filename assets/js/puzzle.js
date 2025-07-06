function checkPuzzle() {
    const sequence = prompt("Code d'accès ?");
    if (sequence === "1337-trkn") {
        window.location.href = "/dashboard";
    } else {
        alert("🔒 Code incorrect. Reviens quand t'es prêt.");
    }
}
