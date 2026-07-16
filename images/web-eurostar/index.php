<?php
// Scénario C (Issue #19) — page volontairement vulnérable à l'injection SQL
// Concaténation directe du paramètre GET, aucune validation/échappement.
$conn = new mysqli("localhost", "eurostar_app", "EurostarApp2026!", "eurostar_db");
if ($conn->connect_error) {
    die("Erreur de connexion : " . $conn->connect_error);
}

$id = $_GET['id'] ?? '1';

// VULNERABLE PAR CONCEPTION — ne pas corriger (objet du scénario C)
$sql = "SELECT id, nom, prenom, numero_reservation, trajet FROM reservations WHERE id = " . $id;
$result = $conn->query($sql);

echo "<html><head><title>Eurostar - Détail réservation</title></head><body>";
echo "<h1>Détail de la réservation</h1>";

if ($result && $result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        echo "<p>ID: " . $row['id'] . "</p>";
        echo "<p>Nom: " . $row['nom'] . " " . $row['prenom'] . "</p>";
        echo "<p>Réservation n°: " . $row['numero_reservation'] . "</p>";
        echo "<p>Trajet: " . $row['trajet'] . "</p>";
    }
} else {
    echo "<p>Aucune réservation trouvée.</p>";
    if ($conn->error) {
        // Message d'erreur SQL exposé volontairement (facilite l'error-based SQLi)
        echo "<p style='color:red'>Erreur SQL: " . $conn->error . "</p>";
    }
}

echo "</body></html>";
$conn->close();
?>
