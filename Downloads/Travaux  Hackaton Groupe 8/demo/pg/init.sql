-- Activer l'extension pgcrypto
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Table des logs de maintenance (une seule colonne chiffrée)
CREATE TABLE maintenance_logs (
    id SERIAL PRIMARY KEY,
    data BYTEA
);

-- Ajouter quelques logs chiffrés
INSERT INTO maintenance_logs(data)
VALUES
(pgp_sym_encrypt(
    '{"machine":"Machine A","panne":"Moteur HS","date":"2026-02-22"}', 
    'cle-secrete'
)),
(pgp_sym_encrypt(
    '{"machine":"Machine B","panne":"Courroie cassée","date":"2026-02-22"}', 
    'cle-secrete'
)),
(pgp_sym_encrypt(
    '{"machine":"Machine C","panne":"Sonde défectueuse","date":"2026-02-22"}', 
    'cle-secrete'
));