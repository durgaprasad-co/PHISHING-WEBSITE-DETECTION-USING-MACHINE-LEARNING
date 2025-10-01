// Dark Mode Toggle Script
document.addEventListener("DOMContentLoaded", function () {
    const themeToggle = document.getElementById("theme-toggle");
    const body = document.body;

    // Function to set the theme
    const setTheme = (theme) => {
        if (theme === "dark") {
            body.classList.add("dark-mode");
            localStorage.setItem("theme", "dark");
        } else {
            body.classList.remove("dark-mode");
            localStorage.setItem("theme", "light");
        }
        // Dispatch a custom event for other components (like Chart.js) to listen to
        const event = new CustomEvent('themeChanged', { detail: { theme: theme } });
        document.dispatchEvent(event);
    };

    // Check for saved theme preference on load
    const savedTheme = localStorage.getItem("theme");
    if (savedTheme) {
        setTheme(savedTheme);
    } else {
        // Default to light mode if no preference is saved
        setTheme("light");
    }

    // Toggle theme when button is clicked
    themeToggle?.addEventListener("click", () => {
        if (body.classList.contains("dark-mode")) {
            setTheme("light");
        } else {
            setTheme("dark");
        }
    });
});