async function request(url, options = {}) {
  const response = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Something went wrong.');
  return payload;
}

document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.querySelector('.login-card form');
  if (loginForm) loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const inputs = loginForm.querySelectorAll('input');
    const button = loginForm.querySelector('button');
    const message = document.querySelector('#form-message');
    button.disabled = true; button.textContent = 'Signing in…';
    try {
      const result = await request('/api/login', { method: 'POST', body: JSON.stringify({ student_id: inputs[0].value, password: inputs[1].value }) });
      window.location.href = result.user.role === 'admin' ? 'admin.html' : 'dashboard.html';
    } catch (error) { message.textContent = error.message; message.className = 'form-message error'; }
    finally { button.disabled = false; button.textContent = 'Sign in to portal'; }
  });

  const contactForm = document.querySelector('#contact-form');
  if (contactForm) contactForm.addEventListener('submit', async (event) => {
    event.preventDefault(); const fields = contactForm.querySelectorAll('input,select,textarea'); const message = document.querySelector('#form-message');
    try { const result = await request('/api/contact', { method: 'POST', body: JSON.stringify({ name: fields[0].value, email: fields[1].value, subject: fields[2].value, message: fields[3].value }) }); message.textContent = result.message; message.className = 'form-message success'; contactForm.reset(); }
    catch (error) { message.textContent = error.message; message.className = 'form-message error'; }
  });
});
