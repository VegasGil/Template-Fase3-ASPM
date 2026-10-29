const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
    const host = req.query.host;
    // VULNERABILIDAD: Inyección de comandos
    exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

app.listen(3000, () => {
    console.log('App de prueba corriendo en puerto 3000');
});