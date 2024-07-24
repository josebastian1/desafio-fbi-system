import express from 'express';
import jwt from 'jsonwebtoken';
import { results } from './data/agentes.js';
import path from 'path';
import { fileURLToPath } from 'url';

// Obtiene la ruta del archivo actual
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;
const SECRET_KEY = 'your-secret-key'; // Cambia esto a una clave secreta segura

// Configura express para analizar datos de formularios y JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configura express para servir archivos estáticos desde la carpeta 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Ruta para autenticación de agentes
app.post('/SignIn', (req, res) => {
  const { email, password } = req.body;
  const agent = results.find(a => a.email === email && a.password === password);

  if (agent) {
    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '2m' });
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Welcome</title>
          <script>
            sessionStorage.setItem('authToken', '${token}');
            setTimeout(() => sessionStorage.removeItem('authToken'), 2 * 60 * 1000); // 2 minutos
          </script>
        </head>
        <body>
          <h1>Welcome, ${email}</h1>
          <a id="restrictedLink" href="/restricted?token=${encodeURIComponent(token)}">Go to Restricted Area</a>
          <script>
            document.getElementById('restrictedLink').addEventListener('click', function(event) {
              event.preventDefault();
              const token = sessionStorage.getItem('authToken');
              if (token) {
                window.location.href = '/restricted?token=' + encodeURIComponent(token);
              } else {
                alert('No token found. Please log in again.');
                window.location.href = '/';
              }
            });
          </script>
        </body>
      </html>
    `);
  } else {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>Invalid Credentials</title>
          <script>
            alert('Invalid credentials. Please try again.');
            window.location.href = '/'; // Redirige al formulario de inicio de sesión
          </script>
        </head>
        <body>
          <h1>Invalid Credentials</h1>
          <p>Please try again.</p>
          <a href="/">Return to Login</a>
        </body>
      </html>
    `);
  }
});

// Ruta restringida
app.get('/restricted', (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res.status(401).send('No token provided.');
  }

  const tokenWithoutBearer = token.startsWith('Bearer ') ? token.slice(7) : token;

  jwt.verify(tokenWithoutBearer, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.error('Token verification error:', err);
      return res.status(401).send('Failed to authenticate token.');
    }

    console.log('Token valid:', decoded);
    res.sendFile(path.join(__dirname, 'public', 'restricted.html'));
  });
});

// Ruta para obtener información del usuario
app.get('/user-info', (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res.status(401).send('No token provided.');
  }

  const tokenWithoutBearer = token.startsWith('Bearer ') ? token.slice(7) : token;

  jwt.verify(tokenWithoutBearer, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).send('Failed to authenticate token.');
    }

    res.json({ email: decoded.email });
  });
});

// Inicia el servidor
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
