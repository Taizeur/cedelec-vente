const express = require('express');
const app = express();

const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('✅ Cedelec Vente est en ligne sur Render 🚀');
});

app.listen(PORT, () => {
  console.log(`Serveur lancé sur le port ${PORT}`);
});