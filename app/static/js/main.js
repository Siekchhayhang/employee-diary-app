// app/static/js/main.js

document.addEventListener("DOMContentLoaded", function () {
  // Get all navbar links
  const navLinks = document.querySelectorAll(".navbar-nav .nav-link");
  const currentLocation = window.location.pathname;

  // Loop through the links and add the 'active' class to the current page's link
  navLinks.forEach((link) => {
    if (link.getAttribute("href") === currentLocation) {
      link.classList.add("active");
    }
  });
});
