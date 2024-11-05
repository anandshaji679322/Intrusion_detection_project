// Firebase configuration and initialization
const firebaseConfig = {
    apiKey: "AIzaSyB9w1uHCNfH9BheeNW9cjMrkeEQuQdg6j4",
    authDomain: "project-35703.firebaseapp.com",
    projectId: "project-35703",
    storageBucket: "project-35703.appspot.com",
    messagingSenderId: "1032417178351",
    appId: "1:1032417178351:web:baa8de9994010a2fb3e11a"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();

// Login Function
function login(event) {
    event.preventDefault();
    
    const email = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    auth.signInWithEmailAndPassword(email, password)
        .then((userCredential) => {
            // Redirect to the admin page or home page
            window.location.href = "home";
        })
        .catch((error) => {
            console.error('Error during sign-in:', error.message);
            alert(error.message);
        });
}

// Register Function
function register(event) {
    event.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    auth.createUserWithEmailAndPassword(email, password)
        .then((userCredential) => {
            // User registration successful
            alert('User registered successfully!');
            window.location.href = "home";
        })
        .catch((error) => {
            console.error('Error during registration:', error.message);
            alert(error.message);
        });
}

// Logout Function
function logout() {
    auth.signOut().then(() => {
        window.location.href = "login.html";
    }).catch((error) => {
        console.error('Error during logout:', error.message);
        alert(error.message);
    });
}