
const API_URL = 'http://0.0.0.0:3004';
let token = '';

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
        });

        const data = await response.json();
        if (response.ok) {
            token = data.access_token;
            document.querySelector('.upload-section').style.display = 'block';
            showMessage('Login successful!', 'success');
        } else {
            showMessage(data.detail, 'error');
        }
    } catch (error) {
        showMessage('Error connecting to server', 'error');
    }
});

document.getElementById('uploadForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const file = document.getElementById('adFile').files[0];
    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch(`${API_URL}/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData
        });

        const data = await response.json();
        if (response.ok) {
            showMessage(`Upload successful! Ad ID: ${data.ad_id}`, 'success');
        } else {
            showMessage(data.detail, 'error');
        }
    } catch (error) {
        showMessage('Error uploading file', 'error');
    }
});

function showMessage(text, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = text;
    messageDiv.className = type;
}
