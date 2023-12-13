
const signUpButton = document.getElementById("signUp");
const signInButton = document.getElementById("signIn");
const container = document.getElementById("container");
const hamburger = document.querySelector(".hamburger");
const navMenu = document.querySelector(".nav-menu");
const registerButton = document.querySelector("#signUp_button")
const loginButton = document.querySelector("#signIn_button")
const form = document.getElementById('form')
const fullname = document.getElementById('fullname')
const email = document.getElementById('email')
const password = document.getElementById('password')

const header = document.querySelector("header");

window.addEventListener("scroll", function() {
    header.classList.toggle("sticky", window.scrollY > 60)
});

// let menu = document.querySelector('#menu-btn');
// let navbar = document.querySelector('.navbar');

// menu.onclick = () => {
//     menu.classList.toggle('bx-x');
//     navbar.classList.toggle('open');
//};

// Hamburger Menu

// hamburger.addEventListener("click", () => {
//     hamburger.classList.toggle("active");
//     navMenu.classList.toggle("active");
// });

document.querySelectorAll(".nav-link").forEach(n => n.addEventListener("click", () => {
    hamburger.classList.remove("active");
    navMenu.classList.remove("active");
}));

// Login Transitioning
signUpButton.addEventListener("click", () =>
  container.classList.add("right-panel-active")
);

signInButton.addEventListener("click", () =>
  container.classList.remove("right-panel-active")
);


// Login Action

// loginButton.addEventListener("click", () =>{
//   return window.location.href = "../dashboard.html"
// })

// registerButton.addEventListener("click", () =>{
//   return window.location.href = "../dashboard.html"
// })

// Form Validation
form.addEventListener('submit', e => {
  e.preventDefault();

  validateInputs();

});

const setError = (element, message) => {
  const inputControl = element.parentElement;
  const errorDisplay = inputControl.querySelector('.error');

  errorDisplay.innerText = message;
  inputControl.classList.add('error');
  inputControl.classList.remove('success')
}

const setSuccess = element => {
  const inputControl = element.parentElement;
  const errorDisplay = inputControl.querySelector('.error');

  errorDisplay.innerText = '';
  inputControl.classList.add('success');
  inputControl.classList.remove('error');
};

const isValidEmail = email => {
  const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(String(email).toLowerCase());
}


const validateInputs = () => {
  const fullnameValue = fullname.Value.trim()
  const emailValue = email.Value.trim()
  const passwordValue = password.Value.trim()

  if(fullname === '') {
    setError(fullname, 'Fullname is required');
  } else {
    setSuccess(fullname);
  }

  if(emailValue === ''){
    setError(email, 'Email is required')
  }if (!isValidEmail(emailValue)) {
    setError(email, 'Provide a valid email address');
  } else {
    setSuccess(email);
  }

  if(passwordValue === '') {
    setError(password, 'Password is required');
  } else if (passwordValue.length < 8 ) {
    setError(password, 'Password must be at least 8 character.')
  } else {
    setSuccess(password);
  }


}


