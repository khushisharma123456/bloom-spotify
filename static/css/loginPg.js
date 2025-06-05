document.getElementById("login-tab").addEventListener("click", function() {
    document.getElementById("login-form").style.display = "flex";
    document.getElementById("signup-form").style.display = "none";
    this.classList.add("active");
    document.getElementById("signup-tab").classList.remove("active");
});

document.getElementById("signup-tab").addEventListener("click", function() {
    document.getElementById("signup-form").style.display = "flex";
    document.getElementById("login-form").style.display = "none";
    this.classList.add("active");
    document.getElementById("login-tab").classList.remove("active");
});