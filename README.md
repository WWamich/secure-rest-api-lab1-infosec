# Информационная безопасность

## Лабораторная работа №1

### Стек

- Node.js / Express 5
- SQLite 
- JWT , bcrypt
- helmet, express-rate-limit, escape-html
- GitHub Actions: npm audit, OWASP Dependency-Check, CodeQL

### Описание API

POST /auth/login: метод для аутентификации пользователя (принимает логин и пароль, возвращает JWT).

```json
{
  "username": "admin",
  "password": "MyStr0ngPass!"
}
```

GET /api/data: метод для получения списка постов. Доступ только у аутентифицированных пользователей, токен передаётся в заголовке Authorization: Bearer <token>.

POST /api/ping: публичный метод без аутентификации. Если в поле message пришло ping, возвращает pong, иначе 400.

```json
{
  "message": "ping"
}
```

```json
{
  "reply": "pong"
}
```

POST /api/posts: метод для создания поста (1..500 символов). Доступ только у аутентифицированных пользователей.

```json
{
  "content": "Hello"
}
```
вызовы
```powershell
'{"message":"ping"}' | curl.exe -i -X POST http://localhost:3000/api/ping -H "Content-Type: application/json" --data-binary "@-"

'{"username":"admin","password":"nagorshkesiditkorol"}' | curl.exe -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" --data-binary "@-"

curl.exe -i http://localhost:3000/api/data

curl.exe http://localhost:3000/api/data -H "Authorization: Bearer <TOKEN>"
```

### Описание реализованных мер защиты

От SQLi код защищён параметризованными запросами prepared statements данные пользователя передаются отдельно от SQL и никогда не конкатенируются в строку запроса.

```js
const findUserByName = db.prepare('SELECT id, username, password_hash FROM users WHERE username = ?');
const user = findUserByName.get(username);
```
От XSS защищён с помощью экранирования пользовательских данных в ответах escapeHtml, дополнительно helmet выставляет защитные заголовки.

```js
app.get('/api/data', authenticate, (req, res) => {
  const posts = listPosts.all().map((p) => ({
    id: p.id,
    content: escapeHtml(p.content),
    author: escapeHtml(p.author),
    created_at: p.created_at,
  }));
  res.json({ posts });
});
```

От Broken Authentication:
пароли хранятся только в виде хэша bcrypt cost 12 

при успешном логине выдаётся JWT (HS256, срок жизни 1 час), секрет берётся из JWT_SECRET

middleware authenticate проверяет подпись и срок действия токена на всех защищённых эндпоинтах, алгоритм при проверке зафиксирован, это для защиты  от alg: none
  
одинаковый ответ Invalid credentials для неверного логина и неверного пароля, для несуществующего пользователя bcrypt всё равно выполняется, нет перечисления пользователей по времени ответа
ограничение количества запросов: 10 попыток логина за 15 минут, 100 запросов в минуту в целом.

```js
function authenticate(req, res, next) {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ msg: 'Missing or malformed Authorization header' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
    req.user = { id: Number(payload.sub), username: payload.username };
    return next();
  } catch {
    return res.status(401).json({ msg: 'Invalid or expired token' });
  }
}
```

также валидация типов и длины входных данных, лимит тела запроса 10 КБ, ошибки `500` без раскрытия внутренней информации, секреты и БД (`.env`, `*.db`) исключены из репозитория.




### Отчеты из pipeline

Автотесты (curl):

![API tests](docs/screenshots/api-tests.png)

npm audit:

![npm audit](docs/screenshots/npm-audit.png)

Dependency-check:

![Dependency-Check](docs/screenshots/dependency-check.png)

CodeQL:

![CodeQL](docs/screenshots/codeql.png)
