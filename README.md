Demonstrates issue where middleware between Authentication and MVC is unable to see user claims if the authentication scheme is not the first one registered.

Steps to reproduce:

- GET localhost:5000/sample/bearer1
   - Output is `{"token": "jwtgoodness"}`

- POST localhost:5000/sample/bearer1
  Authorization: Bearer "jwtgoodness"

- Observe `ContextMiddleware` emits `True` based on the expression `context.User.Identity.IsAuthenticated`

- GET localhost:5000/sample/bearer2
   - Output is `{"token": "jwtgoodness"}`

- POST localhost:5000/sample/bearer2
  Authorization: Bearer "jwtgoodness"

- Observe `ContextMiddleware` emits `False` based on the expression `context.User.Identity.IsAuthenticated`