# Instruções

Container com ubunto e Openbox para montagem de qualquer container com interface gráfica

```bash
docker build -t xvnc-openbox .
docker run -d -p 5901:5901 --name xvnc-openbox-container xvnc-openbox
```

# Autenticação com usuário aluno e senha rnpesr