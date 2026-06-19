#!/usr/bin/env python3
"""Générateur de dorks — produit ~15k-20k dorks uniques."""
from pathlib import Path
import itertools

# ── Cible : Suisse uniquement ──────────────────────────────────
# Utiliser site:.ch sur Google ou gl=ch&cr=countryCH sur Bing
# Les exclusions (-facebook, -google, etc.) sont gérées par le parser
SITE = "site:.ch"
X  = SITE
XB = SITE
XS = SITE
XK = SITE

# ── Régions ────────────────────────────────────────────────────
REG_FR = [
    '"Vaud"', '"Genève"', '"Valais"', '"Neuchâtel"', '"Fribourg"', '"Jura"',
    '"Lausanne"', '"Sion"', '"Nyon"', '"Morges"', '"Yverdon"', '"Bulle"',
    '"Monthey"', '"Martigny"', '"La Chaux-de-Fonds"', '"Sierre"',
]
REG_DE = [
    '"Zürich"', '"Bern"', '"Basel"', '"Luzern"', '"St. Gallen"', '"Winterthur"',
    '"Aarau"', '"Thun"', '"Zug"', '"Chur"', '"Solothurn"', '"Biel"',
    '"Schaffhausen"', '"Frauenfeld"', '"Rapperswil"', '"Uster"',
]
REG_IT = [
    '"Ticino"', '"Lugano"', '"Bellinzona"', '"Locarno"', '"Mendrisio"',
    '"Chiasso"', '"Ascona"', '"Biasca"',
]

# ── Actions FR ─────────────────────────────────────────────────
ACT_FR = [
    '"devis"', '"formulaire"', '"inscription"', '"réservation"',
    '"rendez-vous"', '"commande"', '"abonnement"', '"adhésion"',
    '"demande"', '"contact"', '"offre"', '"préinscription"',
    '"devis gratuit"', '"livraison"', '"prise en charge"',
]

# ── Actions DE ─────────────────────────────────────────────────
ACT_DE = [
    '"Formular"', '"Anmeldung"', '"Termin"', '"Offerte"', '"Anfrage"',
    '"Bestellung"', '"Reservation"', '"Buchung"', '"Kontakt"',
    '"Abonnement"', '"Abo"', '"Mitgliedschaft"', '"Angebot"',
]

# ── Actions IT ─────────────────────────────────────────────────
ACT_IT = [
    '"modulo"', '"iscrizione"', '"prenotazione"', '"appuntamento"',
    '"preventivo"', '"richiesta"', '"ordine"', '"abbonamento"', '"contatto"',
]

# ── Secteurs FR ────────────────────────────────────────────────
SECT_FR = [
    '("plombier" OR "électricien" OR "chauffagiste")',
    '("menuisier" OR "charpentier" OR "ébéniste")',
    '("peintre" OR "carreleur" OR "plâtrier")',
    '("serrurier" OR "vitrier" OR "ferronnier")',
    '("couvreur" OR "zingueur" OR "ramoneur")',
    '("pisciniste" OR "piscine" OR "spa privé")',
    '("alarme" OR "sécurité" OR "vidéosurveillance")',
    '("rénovation" OR "travaux" OR "réhabilitation")',
    '("isolation" OR "façade" OR "toiture")',
    '("chauffage" OR "pompe à chaleur" OR "solaire thermique")',
    '("déménagement" OR "déménageur" OR "transport déménagement")',
    '("garde-meuble" OR "self-stockage" OR "stockage")',
    '("nettoyage" OR "conciergerie" OR "entretien")',
    '("femme de ménage" OR "aide ménagère" OR "service ménager")',
    '("nettoyage fin de bail" OR "nettoyage de chantier")',
    '("lavage de vitres" OR "nettoyage de façade")',
    '("jardinier" OR "paysagiste" OR "jardinage")',
    '("entretien jardin" OR "tonte" OR "élagage")',
    '("aménagement jardin" OR "plantation" OR "arrosage automatique")',
    '("vétérinaire" OR "clinique vétérinaire")',
    '("physiothérapeute" OR "kinésithérapeute")',
    '("ostéopathe" OR "chiropracteur")',
    '("acupuncteur" OR "naturopathe" OR "homéopathe")',
    '("psychologue" OR "thérapeute" OR "psychiatre")',
    '("ergothérapeute" OR "logopédiste")',
    '("diététicien" OR "nutritionniste")',
    '("infirmier" OR "soins à domicile")',
    '("sage-femme" OR "maïeuticienne")',
    '("pharmacie" OR "parapharmacie")',
    '("spa" OR "massage" OR "relaxation")',
    '("esthétique" OR "esthéticienne" OR "soins du visage")',
    '("manucure" OR "pédicure" OR "onglerie")',
    '("épilation" OR "laser" OR "photoépilation")',
    '("avocat" OR "étude d\'avocat" OR "cabinet juridique")',
    '("notaire" OR "étude notariale")',
    '("huissier" OR "mandataire" OR "médiateur")',
    '("fiduciaire" OR "comptable" OR "expert-comptable")',
    '("conseiller financier" OR "planification financière")',
    '("gestion de patrimoine" OR "gestion d\'actifs")',
    '("courtier" OR "courtier en hypothèques")',
    '("fromagerie" OR "fromage artisanal" OR "fromage AOP")',
    '("vignoble" OR "vigneron" OR "cave viticole")',
    '("boulangerie" OR "pâtisserie artisanale")',
    '("confiserie" OR "chocolatier" OR "confiseur")',
    '("boucher" OR "boucherie" OR "charcuterie artisanale")',
    '("traiteur" OR "buffet" OR "catering")',
    '("épicerie fine" OR "produits locaux" OR "circuit court")',
    '("maraîcher" OR "ferme" OR "agriculture")',
    '("apiculteur" OR "miel" OR "apiculture")',
    '("brasserie artisanale" OR "microbrasserie")',
    '("hôtel" OR "boutique hôtel" OR "hôtel de charme")',
    '("pension" OR "auberge" OR "maison d\'hôtes")',
    '("bed and breakfast" OR "B&B" OR "chambre d\'hôtes")',
    '("gîte" OR "chalet de vacances" OR "appartement touristique")',
    '("camping" OR "glamping" OR "mobilhome")',
    '("restaurant" OR "bistrot" OR "brasserie")',
    '("pizzeria" OR "cuisine italienne")',
    '("sushi" OR "japonais" OR "asiatique")',
    '("veggie" OR "végétarien" OR "vegan")',
    '("agence de voyage" OR "voyage sur mesure")',
    '("guide touristique" OR "guide de montagne")',
    '("parapente" OR "deltaplane" OR "vol libre")',
    '("rafting" OR "kayak" OR "canoë")',
    '("accrobranche" OR "tyrolienne" OR "zip-line")',
    '("club de golf" OR "golf" OR "green fee")',
    '("club de tennis" OR "padel" OR "squash")',
    '("voile" OR "navigation" OR "club nautique")',
    '("équitation" OR "club hippique" OR "cours d\'équitation")',
    '("yoga" OR "pilates" OR "méditation")',
    '("crossfit" OR "musculation" OR "fitness")',
    '("natation" OR "piscine privée" OR "aquagym")',
    '("escalade" OR "boulder" OR "via ferrata")',
    '("danse" OR "école de danse" OR "cours de danse")',
    '("arts martiaux" OR "judo" OR "karaté")',
    '("boxe" OR "kickboxing" OR "MMA")',
    '("école de ski" OR "moniteur de ski" OR "snowboard")',
    '("cyclisme" OR "vélo" OR "VTT")',
    '("auto-école" OR "cours de conduite" OR "permis")',
    '("cours de langue" OR "école de langue")',
    '("école de musique" OR "cours de piano" OR "cours de guitare")',
    '("cours de chant" OR "cours de solfège")',
    '("cours de dessin" OR "cours de peinture" OR "arts plastiques")',
    '("cours particuliers" OR "soutien scolaire" OR "tutorat")',
    '("formation professionnelle" OR "reconversion")',
    '("salon de coiffure" OR "coiffeur" OR "coloriste")',
    '("barbier" OR "barber shop")',
    '("tatouage" OR "studio de tatouage")',
    '("piercing" OR "studio de piercing")',
    '("créateur" OR "styliste" OR "couturier")',
    '("retouche" OR "tailleur" OR "couture")',
    '("architecte" OR "bureau d\'architecture")',
    '("géomètre" OR "expertise immobilière")',
    '("décorateur" OR "home staging" OR "décoration intérieure")',
    '("cuisiniste" OR "cuisine sur mesure")',
    '("garage" OR "garagiste" OR "mécanicien")',
    '("carrosserie" OR "carrossier" OR "débosselage")',
    '("pneumatiques" OR "pneus" OR "jantes")',
    '("contrôle technique" OR "expertise auto")',
    '("location de voiture" OR "location de véhicule")',
    '("taxi" OR "chauffeur privé" OR "VTC")',
    '("imprimerie" OR "impression" OR "sérigraphie")',
    '("signalétique" OR "enseigne" OR "PLV")',
    '("traduction" OR "traducteur" OR "interprète")',
    '("photographe" OR "photographe professionnel")',
    '("vidéaste" OR "production vidéo" OR "drone")',
    '("graphiste" OR "designer graphique")',
    '("webmaster" OR "développeur web" OR "agence web")',
    '("événementiel" OR "organisation d\'événements")',
    '("pension pour chiens" OR "garderie chiens")',
    '("toilettage" OR "toiletteur" OR "grooming")',
    '("éducateur canin" OR "dressage chien")',
    '("crèche" OR "garderie" OR "halte-garderie")',
    '("baby-sitter" OR "garde d\'enfants" OR "nounou")',
    '("colonie de vacances" OR "camp de vacances")',
    '("aide à domicile" OR "maintien à domicile")',
    '("EMS" OR "maison de retraite" OR "résidence seniors")',
    '("bijouterie" OR "joaillerie" OR "horlogerie")',
    '("opticien" OR "optique" OR "lunettes")',
    '("audioprothésiste" OR "appareils auditifs")',
    '("pressing" OR "teinturerie" OR "nettoyage vêtements")',
    '("serrurier" OR "dépannage serrure" OR "ouverture de porte")',
    '("débarras" OR "débarras d\'appartement")',
    '("extermination" OR "désinsectisation" OR "dératisation")',
]

# ── Secteurs DE ────────────────────────────────────────────────
SECT_DE = [
    '("Sanitär" OR "Heizung" OR "Klima")',
    '("Elektriker" OR "Elektroinstallateur")',
    '("Schreiner" OR "Zimmermann" OR "Tischler")',
    '("Maler" OR "Gipser" OR "Bodenleger")',
    '("Dachdecker" OR "Spengler" OR "Kaminfeger")',
    '("Alarm" OR "Sicherheit" OR "Videoüberwachung")',
    '("Renovation" OR "Umbau" OR "Ausbau")',
    '("Reinigung" OR "Hauswartung" OR "Gebäudereinigung")',
    '("Umzug" OR "Umzugsfirma" OR "Möbeltransport")',
    '("Gärtner" OR "Gartengestaltung" OR "Gartenunterhalt")',
    '("Zahnarzt" OR "Zahnarztpraxis" OR "Kieferorthopäde")',
    '("Arzt" OR "Hausarzt" OR "Allgemeinmedizin")',
    '("Tierarzt" OR "Tierarztpraxis" OR "Tierklinik")',
    '("Physiotherapeut" OR "Physiotherapie")',
    '("Osteopath" OR "Chiropraktiker")',
    '("Psychologe" OR "Psychotherapeut")',
    '("Ernährungsberater" OR "Diätassistentin")',
    '("Apotheke" OR "Drogerie")',
    '("Optiker" OR "Augenoptiker" OR "Kontaktlinsen")',
    '("Hörgeräte" OR "Hörakustiker")',
    '("Coiffeur" OR "Friseur" OR "Hairstudio")',
    '("Massage" OR "Massagepraxis" OR "Wellness")',
    '("Kosmetik" OR "Kosmetikstudio" OR "Schönheitssalon")',
    '("Nagelstudio" OR "Maniküre" OR "Pediküre")',
    '("Tattoo" OR "Piercingstudio")',
    '("Fitnessstudio" OR "Gym" OR "Sportclub")',
    '("Yoga" OR "Pilates" OR "Meditation")',
    '("Tennis" OR "Tennisclub" OR "Padel")',
    '("Golf" OR "Golfclub" OR "Greenfee")',
    '("Kampfsport" OR "Judo" OR "Karate")',
    '("Reitschule" OR "Reiten" OR "Reitstall")',
    '("Schwimmkurs" OR "Schwimmunterricht")',
    '("Fahrschule" OR "Fahrstunden" OR "Fahrlehrer")',
    '("Sprachkurs" OR "Sprachschule" OR "Englischkurs")',
    '("Musikschule" OR "Klavierunterricht" OR "Gitarrenunterricht")',
    '("Nachhilfe" OR "Privatunterricht" OR "Tutoring")',
    '("Tanzschule" OR "Tanzkurs" OR "Tanzunterricht")',
    '("Restaurant" OR "Gasthaus" OR "Beiz")',
    '("Bäckerei" OR "Konditorei" OR "Confiserie")',
    '("Catering" OR "Partyservice" OR "Lieferservice")',
    '("Hotel" OR "Pension" OR "Gasthaus")',
    '("Ferienwohnung" OR "Ferienhaus" OR "Chalet")',
    '("Camping" OR "Glamping")',
    '("Rechtsanwalt" OR "Anwaltskanzlei" OR "Notar")',
    '("Treuhänder" OR "Treuhandgesellschaft" OR "Buchhaltung")',
    '("Versicherungsberater" OR "Versicherungsmakler")',
    '("Fotograf" OR "Fotografin" OR "Fotostudio")',
    '("Druckerei" OR "Beschriftung" OR "Werbetechnik")',
    '("Übersetzer" OR "Dolmetscher" OR "Übersetzungsbüro")',
    '("Webdesign" OR "Webentwicklung")',
    '("Garage" OR "Autowerkstatt" OR "Autoservice")',
    '("Carrosserie" OR "Karosserie" OR "Unfallreparatur")',
    '("Pneus" OR "Reifen" OR "Felgen")',
    '("Taxi" OR "Chauffeur" OR "Fahrdienst")',
    '("Umzug" OR "Möbelpacker")',
    '("Schädlingsbekämpfung" OR "Kammerjäger")',
    '("Bestattung" OR "Bestattungsunternehmen")',
    '("Schlüsseldienst" OR "Schloss" OR "Türöffnung")',
    '("Hundesalon" OR "Hundefriseur" OR "Tierpflege")',
    '("Hundepension" OR "Hundetagesstätte")',
    '("Krippe" OR "Kita" OR "Kinderbetreuung")',
    '("Bijouterie" OR "Schmuck" OR "Uhren")',
]

# ── Secteurs IT ────────────────────────────────────────────────
SECT_IT = [
    '("dentista" OR "studio dentistico")',
    '("medico" OR "medico di famiglia")',
    '("fisioterapista" OR "fisioterapia")',
    '("osteopata" OR "chiropratico")',
    '("psicologo" OR "psicoterapeuta")',
    '("farmacia" OR "erboristeria")',
    '("ottico" OR "ottica")',
    '("veterinario" OR "clinica veterinaria")',
    '("parrucchiere" OR "salone di bellezza")',
    '("estetista" OR "centro estetico")',
    '("massaggio" OR "centro benessere")',
    '("tatuaggi" OR "studio tattoo")',
    '("palestra" OR "fitness" OR "centro sportivo")',
    '("yoga" OR "pilates" OR "meditazione")',
    '("idraulico" OR "impianti idraulici")',
    '("elettricista" OR "impianti elettrici")',
    '("falegname" OR "carpentiere" OR "ebanista")',
    '("imbianchino" OR "pittore edile")',
    '("pulizie" OR "impresa di pulizie")',
    '("trasloco" OR "ditta di traslochi")',
    '("giardiniere" OR "giardinaggio")',
    '("ristorante" OR "trattoria" OR "osteria")',
    '("pizzeria" OR "pizza d\'asporto")',
    '("catering" OR "servizio catering")',
    '("panificio" OR "pasticceria")',
    '("avvocato" OR "studio legale" OR "notaio")',
    '("commercialista" OR "studio commercialista")',
    '("traduttore" OR "interprete")',
    '("fotografo" OR "studio fotografico")',
    '("autoscuola" OR "scuola guida")',
    '("hotel" OR "pensione" OR "albergo")',
    '("appartamento vacanze" OR "chalet")',
    '("gioielleria" OR "orologeria")',
    '("ottica" OR "lenti a contatto")',
]

# ── Dorks scanner-spécifiques (LFI, RCE, SSTI, frameworks) ───
SCANNER_DORKS = [
    # LFI params
    'inurl:"?file=" inurl:".php"',
    'inurl:"?path=" inurl:".php"',
    'inurl:"?include=" inurl:".php"',
    'inurl:"?template=" inurl:".php"',
    'inurl:"?lang=" inurl:".php"',
    'inurl:"?language=" inurl:".php"',
    'inurl:"?dir=" inurl:".php"',
    'inurl:"?load=" inurl:".php"',
    'inurl:"?pg=" inurl:".php"',
    'inurl:"?filename=" inurl:".php"',
    'inurl:"?download=" inurl:".php"',
    'inurl:"?read=" inurl:".php"',
    'inurl:"?document=" inurl:".php"',
    'inurl:"?fichier=" inurl:".php"',
    # RCE / command injection
    'inurl:"?cmd=" inurl:".php"',
    'inurl:"?exec=" inurl:".php"',
    'inurl:"?command=" inurl:".php"',
    'inurl:"?ping=" inurl:".php"',
    'inurl:"?execute=" inurl:".php"',
    'inurl:"?shell=" inurl:".php"',
    'inurl:"?ip=" inurl:".php" ("ping" OR "traceroute" OR "nslookup")',
    'inurl:"?host=" inurl:".php" ("test" OR "check" OR "verify")',
    'inurl:"?domain=" inurl:".php" ("check" OR "test" OR "lookup")',
    # SSTI
    'inurl:"?tpl=" inurl:".php"',
    'inurl:"?skin=" inurl:".php"',
    '"Smarty" ("formulaire" OR "devis" OR "contact") inurl:".php"',
    'inurl:"/preview" inurl:".php"',
    # Frameworks PHP
    'inurl:"/public/index.php"',
    'inurl:"/app_dev.php"',
    '"Laravel" inurl:"login"',
    '"Symfony" inurl:"login"',
    '"Powered by CakePHP"',
    # Frameworks Python
    'inurl:"/admin/" "Django administration"',
    '"DisallowedHost" "Django"',
    '"Werkzeug Debugger"',
    'inurl:"/__debug__/"',
    # Erreurs d'exécution
    '"Fatal error:" "on line"',
    '"Warning: include("',
    '"Warning: require("',
    '"failed to open stream: No such file or directory"',
    '"open_basedir restriction in effect"',
    '"OperationalError" "no such table"',
    '"sqlite3.OperationalError"',
    # SQLi supplémentaires
    '"near" "syntax error" "SQLite"',
    '"unrecognized token" "SQLite"',
    '"XPATH syntax error"',
    '"Column count doesn\'t match"',
    '"Unknown column" "in \'field list\'"',
    '"operator does not exist" "integer"',
    # Open redirect
    'inurl:"?redirect=" inurl:".php"',
    'inurl:"?return=" inurl:".php"',
    'inurl:"?next=" inurl:".php"',
    'inurl:"?goto=" inurl:".php"',
    'inurl:"?dest=" inurl:".php"',
    'inurl:"?redir=" inurl:".php"',
    'inurl:"?callback=" inurl:".php"',
    'inurl:"?return_url=" inurl:".php"',
    # APIs non documentées
    'inurl:"/api/users"',
    'inurl:"/api/admin"',
    'inurl:"/api/config"',
    'inurl:"/api/debug"',
    'inurl:"?format=json" inurl:".php"',
    'inurl:"?output=json" inurl:".php"',
    'inurl:"/ajax/" inurl:".php"',
    # Fichiers sensibles
    'intitle:"index of" "users.sql"',
    'intitle:"index of" "accounts.sql"',
    'intitle:"index of" "passwords.sql"',
    '"DB_HOST" "DB_PASSWORD" filetype:env',
    '"define(\'DB_PASSWORD\'" filetype:php',
    # CMS plugins vulnérables
    'inurl:"/wp-content/plugins/" inurl:"?id="',
    'inurl:"/wp-content/plugins/revslider"',
    'inurl:"?option=com_contact"',
    'inurl:"?option=com_search"',
    'inurl:"?q=user/login"',
    'inurl:"?q=search/node"',
]


# ── Dorks techniques ───────────────────────────────────────────
TECH_DORKS = [
    # SQLi GET params PHP
    'inurl:"?id=" inurl:".php"',
    'inurl:"?cat=" inurl:".php"',
    'inurl:"?page=" inurl:".php"',
    'inurl:"?article=" inurl:".php"',
    'inurl:"?product=" inurl:".php"',
    'inurl:"?item=" inurl:".php"',
    'inurl:"?news=" inurl:".php"',
    'inurl:"?ref=" inurl:".php"',
    'inurl:"?user=" inurl:".php"',
    'inurl:"?action=" inurl:".php"',
    'inurl:"?p=" inurl:".php"',
    'inurl:"?pid=" inurl:".php"',
    'inurl:"?cid=" inurl:".php"',
    'inurl:"?nid=" inurl:".php"',
    'inurl:"?sid=" inurl:".php"',
    'inurl:"index.php?id="',
    'inurl:"view.php?id="',
    'inurl:"detail.php?id="',
    'inurl:"produit.php?id="',
    'inurl:"article.php?id="',
    'inurl:"news.php?id="',
    'inurl:"page.php?id="',
    'inurl:"show.php?id="',
    'inurl:"fiche.php?id="',
    'inurl:"afficher.php?id="',
    'inurl:"produit.php?ref="',
    'inurl:"categorie.php?id="',
    'inurl:"category.php?id="',
    'inurl:"galerie.php?id="',
    'inurl:"photo.php?id="',
    'inurl:"event.php?id="',
    'inurl:"membre.php?id="',
    'inurl:"profil.php?id="',
    'inurl:"blog.php?id="',
    'inurl:"post.php?id="',
    'inurl:"forum.php?id="',
    'inurl:"topic.php?id="',
    'inurl:"comment.php?id="',
    'inurl:"download.php?id="',
    'inurl:"fichier.php?id="',
    'inurl:"file.php?id="',
    # ASP/ASPX params
    'inurl:"?id=" inurl:".asp"',
    'inurl:"?id=" inurl:".aspx"',
    'inurl:"Default.aspx?id="',
    'inurl:"page.aspx?id="',
    'inurl:"detail.aspx?id="',
    'inurl:"product.aspx?id="',
    # XSS search forms
    'inurl:"?search=" inurl:".php"',
    'inurl:"?q=" inurl:".php"',
    'inurl:"?query=" inurl:".php"',
    'inurl:"?keyword=" inurl:".php"',
    'inurl:"recherche.php"',
    'inurl:"search.php"',
    'intitle:"résultats de recherche" inurl:".php"',
    'intitle:"Suchergebnisse" inurl:".php"',
    'intitle:"risultati ricerca" inurl:".php"',
    # Auth forms
    'inurl:"login.php"',
    'inurl:"connexion.php"',
    'inurl:"/espace-client" inurl:".php"',
    'inurl:"/mon-compte" inurl:".php"',
    'inurl:"/membre" inurl:".php"',
    'inurl:"signin.php"',
    'inurl:"authenticate.php"',
    'inurl:"/login" inurl:".php"',
    'inurl:"/connexion" inurl:".php"',
    'intitle:"connexion" inurl:".php"',
    'intitle:"Anmeldung" inurl:".php"',
    'inurl:"register.php"',
    'inurl:"inscription.php"',
    'inurl:"/register" inurl:".php"',
    # Admin panels
    'inurl:"/phpmyadmin"',
    'inurl:"/adminer"',
    'inurl:"/adminer.php"',
    'inurl:"/pma/"',
    'inurl:"/dbadmin/"',
    'inurl:"/wp-admin"',
    'inurl:"/administrator"',
    'inurl:"/admin" inurl:".php"',
    'inurl:"/backend" inurl:".php"',
    'inurl:"/panel" inurl:".php"',
    'inurl:"/dashboard" inurl:".php"',
    'inurl:"/controlpanel"',
    'inurl:"/cpanel"',
    'inurl:"/webmail"',
    # Sensitive files
    'intitle:"index of" ".sql"',
    'intitle:"index of" ".env"',
    'intitle:"index of" ".bak"',
    'intitle:"index of" "config.php"',
    'intitle:"index of" "wp-config.php"',
    'intitle:"index of" "database"',
    'intitle:"index of" "backup"',
    'intitle:"index of" ".log"',
    'intitle:"index of" "passwd"',
    'intitle:"index of" "credentials"',
    'inurl:"phpinfo.php"',
    'inurl:"info.php" "PHP Version"',
    'intitle:"PHP Version" "Server API"',
    'inurl:"/.git"',
    'inurl:".env" "DB_PASSWORD"',
    'inurl:"config.php.bak"',
    'inurl:"dump.sql"',
    'inurl:"database.sql"',
    'inurl:"backup.sql"',
    'inurl:"/backup/" intitle:"index of"',
    'inurl:"/logs/" intitle:"index of"',
    # DB errors
    '"You have an error in your SQL syntax"',
    '"mysql_fetch_array()"',
    '"Warning: mysql_"',
    '"mysqli_fetch" "Warning"',
    '"ORA-01756"',
    '"pg_query()" "Warning"',
    '"SQLite3::query" "Warning"',
    '"ODBC SQL Server Driver"',
    '"supplied argument is not a valid MySQL"',
    '"Uncaught PDOException"',
    '"mysql_num_rows()" "Warning"',
    '"pg_exec()" "Warning"',
    # API endpoints
    'inurl:"/api/v1/"',
    'inurl:"/api/v2/"',
    'inurl:"/api/v3/"',
    'inurl:"/rest/api/"',
    'inurl:"/swagger"',
    'inurl:"/swagger-ui"',
    'inurl:"/graphql"',
    'inurl:"/api/" inurl:".php"',
    # File upload
    'inurl:"upload.php"',
    'inurl:"uploader.php"',
    'inurl:"file_upload.php"',
    'inurl:"upload" inurl:".php" ("fichier" OR "télécharger")',
    'intitle:"upload" inurl:".php"',
    # WordPress
    'inurl:"wp-login.php"',
    'inurl:"/wp-json/wp/v2/users"',
    'inurl:"/wp-content/uploads/" intitle:"index of"',
    'inurl:"?author=" inurl:".php"',
    'inurl:"/wp-json/"',
    'inurl:"xmlrpc.php"',
    # Joomla / CMS
    'inurl:"index.php?option=com_"',
    'inurl:"?view=" inurl:"?layout=" inurl:".php"',
    'inurl:"?module=" inurl:"?func="',
    'inurl:"index.php?option=com_user"',
    # Intitle/inurl patterns
    'intitle:"formulaire de contact"',
    'intitle:"demande de devis"',
    'intitle:"prise de rendez-vous"',
    'intitle:"réservation en ligne"',
    'intitle:"formulaire d\'inscription"',
    'intitle:"commander en ligne"',
    'intitle:"Angebot anfordern"',
    'intitle:"Termin buchen"',
    'intitle:"Anmeldung" inurl:formular',
    'intitle:"prenota online"',
    'inurl:"/devis"',
    'inurl:"/inscription"',
    'inurl:"/reservation"',
    'inurl:"contact.php"',
    'inurl:"formulaire.php"',
    'inurl:"devis.php"',
    'inurl:"kontakt.php"',
    'inurl:"contatto.php"',
    'inurl:"/rendez-vous"',
    'inurl:"?page=contact"',
]


# ── Niches CH — mots-clés multilingues groupés, site:.ch suffit ──
# Format : (keyword_query, label)
# keyword_query = ce qui va dans la dork après l'indicateur technique
# Couvre FR/DE/IT en une seule query via OR — pas de listes séparées

NICHES_CH = [
    # ── Dentistes ──────────────────────────────────────────────
    ('("Zahnarzt" OR "Zahnarztpraxis" OR "dentiste" OR "cabinet dentaire" OR "studio dentistico")', 'dentiste'),
    ('("Zahnklinik" OR "clinique dentaire" OR "clinica dentale" OR "Kieferorthopäde" OR "orthodontiste")', 'dentiste-clinique'),
    ('("Dentalhygiene" OR "hygiène dentaire" OR "igiene dentale")', 'dentiste-hygiene'),

    # ── Bijouterie ─────────────────────────────────────────────
    ('("Bijouterie" OR "Juwelier" OR "Juweliergeschäft" OR "gioielleria" OR "bijoutier")', 'bijouterie'),
    ('("bijoux" OR "Schmuck" OR "gioielli" OR "jewelry")', 'bijoux'),
    ('("joaillerie" OR "Goldschmied" OR "oreficeria" OR "orfèvre")', 'joaillerie'),
    ('("bague" OR "Ring" OR "anello" OR "collier" OR "Halskette" OR "pendentif")', 'bijoux-produits'),
    ('("diamant" OR "Diamant" OR "diamante" OR "saphir" OR "Saphir" OR "rubis")', 'pierreries'),

    # ── Horlogerie / Montres ────────────────────────────────────
    ('("horlogerie" OR "Uhren" OR "orologeria" OR "montre" OR "Uhr" OR "orologio")', 'horlogerie'),
    ('("horloger" OR "Uhrmacher" OR "orologiaio" OR "watchmaker")', 'horloger'),
    ('("réparation montre" OR "Uhrenreparatur" OR "riparazione orologi")', 'reparation-montre'),
    ('("boutique montre" OR "Uhrengeschäft" OR "negozio orologi" OR "watch shop")', 'boutique-montre'),
    ('("montre de luxe" OR "Luxusuhr" OR "orologio di lusso" OR "luxury watch")', 'montre-luxe'),

    # ── Entreprises générales ───────────────────────────────────
    ('("SARL" OR "SA" OR "GmbH" OR "AG" OR "Sàrl" OR "Srl")', 'entreprise-forme-juridique'),
    ('("entreprise" OR "Unternehmen" OR "azienda" OR "société" OR "Firma")', 'entreprise-generale'),
    ('("PME" OR "KMU" OR "piccola impresa" OR "small business")', 'pme'),
    ('("devis en ligne" OR "Online-Offerte" OR "preventivo online" OR "quote online")', 'devis-en-ligne'),
    ('("commande en ligne" OR "Online-Bestellung" OR "ordine online" OR "shop")', 'commande-en-ligne'),
    ('("espace client" OR "Kundenbereich" OR "area clienti" OR "my account")', 'espace-client'),
    ('("intranet" OR "extranet" OR "portail entreprise" OR "Unternehmensportal")', 'intranet'),

    # ── Services B2B ────────────────────────────────────────────
    ('("fiduciaire" OR "Treuhand" OR "fiduciaria" OR "comptable" OR "Buchhaltung")', 'fiduciaire'),
    ('("avocat" OR "Rechtsanwalt" OR "avvocato" OR "Anwalt" OR "notaire" OR "Notar")', 'avocat'),
    ('("architecte" OR "Architekt" OR "architetto" OR "bureau d\'architecture")', 'architecte'),
    ('("agence web" OR "Webagentur" OR "agenzia web" OR "webdesign")', 'agence-web'),
    ('("agence de communication" OR "Kommunikationsagentur" OR "agenzia comunicazione")', 'agence-com'),
    ('("courtier" OR "Makler" OR "mediatore" OR "assurance" OR "Versicherung")', 'courtier'),
    ('("géomètre" OR "Geometer" OR "geometra" OR "topographe")', 'geometre'),
    ('("imprimerie" OR "Druckerei" OR "tipografia" OR "impression")', 'imprimerie'),

    # ── Commerce de détail / E-commerce ────────────────────────
    ('("boutique en ligne" OR "Online-Shop" OR "negozio online" OR "webshop")', 'boutique-en-ligne'),
    ('("vente en ligne" OR "Online-Verkauf" OR "vendita online" OR "e-commerce")', 'vente-en-ligne'),
    ('("articles de sport" OR "Sportartikel" OR "articoli sportivi")', 'sport-retail'),
    ('("librairie" OR "Buchhandlung" OR "libreria" OR "livres" OR "Bücher")', 'librairie'),
    ('("fleuriste" OR "Blumenladen" OR "fiorista" OR "fleurs" OR "Blumen")', 'fleuriste'),
    ('("animalerie" OR "Tierhandlung" OR "negozio animali" OR "pet shop")', 'animalerie'),
    ('("optique" OR "Optiker" OR "ottico" OR "lunettes" OR "Brillen")', 'optique'),
    ('("pharmacie" OR "Apotheke" OR "farmacia" OR "parapharmacie")', 'pharmacie'),

    # ── Santé & Médical ─────────────────────────────────────────
    ('("cabinet médical" OR "Arztpraxis" OR "studio medico" OR "médecin" OR "Arzt")', 'medecin'),
    ('("clinique" OR "Klinik" OR "clinica" OR "centre médical" OR "Gesundheitszentrum")', 'clinique'),
    ('("physiothérapeute" OR "Physiotherapeut" OR "fisioterapista" OR "kiné")', 'physio'),
    ('("ostéopathe" OR "Osteopath" OR "osteopata" OR "chiropracteur" OR "Chiropraktiker")', 'osteo'),
    ('("psychologue" OR "Psychologe" OR "psicologo" OR "thérapeute" OR "Therapeut")', 'psy'),
    ('("vétérinaire" OR "Tierarzt" OR "veterinario" OR "clinique vétérinaire")', 'veto'),

    # ── Restauration & Hôtellerie ───────────────────────────────
    ('("restaurant" OR "Restaurant" OR "ristorante" OR "Gasthaus" OR "bistrot")', 'restaurant'),
    ('("hôtel" OR "Hotel" OR "albergo" OR "pension" OR "Pension")', 'hotel'),
    ('("chambre d\'hôtes" OR "Bed and Breakfast" OR "Gasthaus" OR "B&B")', 'bb'),
    ('("traiteur" OR "Catering" OR "catering" OR "Partyservice")', 'traiteur'),
    ('("boulangerie" OR "Bäckerei" OR "panificio" OR "pâtisserie" OR "Konditorei")', 'boulangerie'),

    # ── Immobilier ──────────────────────────────────────────────
    ('("agence immobilière" OR "Immobilienmakler" OR "agenzia immobiliare")', 'immo'),
    ('("location appartement" OR "Wohnungsvermietung" OR "affitto appartamento")', 'location-immo'),
    ('("gérance immobilière" OR "Immobilienverwaltung" OR "amministrazione immobiliare")', 'gerance'),

    # ── Formation & Education ───────────────────────────────────
    ('("école privée" OR "Privatschule" OR "scuola privata" OR "centre de formation")', 'ecole-privee'),
    ('("soutien scolaire" OR "Nachhilfe" OR "ripetizioni" OR "cours particuliers")', 'soutien-scolaire'),
    ('("auto-école" OR "Fahrschule" OR "autoscuola" OR "permis de conduire")', 'auto-ecole'),
    ('("école de langue" OR "Sprachschule" OR "scuola di lingue" OR "cours de langues")', 'ecole-langue'),

    # ── Sport & Loisirs ─────────────────────────────────────────
    ('("club sportif" OR "Sportverein" OR "associazione sportiva" OR "club de sport")', 'club-sport'),
    ('("salle de sport" OR "Fitnessstudio" OR "palestra" OR "gym" OR "fitness")', 'fitness'),
    ('("piscine" OR "Schwimmbad" OR "piscina" OR "aquapark")', 'piscine'),
    ('("tennis" OR "Tennisclub" OR "tennis club" OR "padel")', 'tennis'),
    ('("golf" OR "Golfclub" OR "golf club" OR "green fee")', 'golf'),
    ('("école de ski" OR "Skischule" OR "scuola sci" OR "moniteur de ski")', 'ski'),
    ('("école de danse" OR "Tanzschule" OR "scuola di danza" OR "cours de danse")', 'danse'),

    # ── Beauté & Bien-être ──────────────────────────────────────
    ('("salon de coiffure" OR "Coiffeursalon" OR "salone parrucchiere" OR "coiffeur")', 'coiffeur'),
    ('("spa" OR "Wellness" OR "benessere" OR "centre de bien-être" OR "institut beauté")', 'spa'),
    ('("esthéticienne" OR "Kosmetikerin" OR "estetista" OR "soins du visage")', 'esthetique'),
]

# ── Indicateurs techniques — vrais vecteurs d'injection ────────
_TECH_INDICATORS = [
    ('inurl:"?id=" inurl:".php"',     'sqli-id'),
    ('inurl:"?cat=" inurl:".php"',    'sqli-cat'),
    ('inurl:"?page=" inurl:".php"',   'sqli-page'),
    ('inurl:"?search=" inurl:".php"', 'sqli-search'),
    ('inurl:"?ref=" inurl:".php"',    'sqli-ref'),
    ('inurl:"login.php"',             'auth'),
    ('inurl:"inscription.php"',       'register'),
    ('inurl:"register.php"',          'register-en'),
    ('inurl:"reservation.php"',       'booking'),
    ('inurl:"booking.php"',           'booking-en'),
    ('inurl:"produit.php"',           'product'),
    ('inurl:"fiche.php"',             'fiche'),
    ('inurl:"detail.php"',            'detail'),
    ('inurl:"catalogue.php"',         'catalogue'),
    ('inurl:"panier.php"',            'cart'),
    ('inurl:"compte.php"',            'account'),
    ('inurl:"espace-client"',         'espace-client'),
    ('inurl:"wp-login.php"',          'wp-login'),
    ('inurl:"/wp-content/"',          'wp-content'),
    ('inurl:"index.php?id="',         'sqli-index-id'),
]


def generate():
    dorks = set()

    # Dorks techniques pures — site:.ch
    for d in TECH_DORKS:
        dorks.add(f'{d} {SITE}' if SITE not in d else d)

    # Dorks scanner-spécifiques — site:.ch
    for d in SCANNER_DORKS:
        dorks.add(f'{d} {SITE}' if SITE not in d else d)

    # Niches CH multilingues × indicateurs techniques
    for niche_q, _ in NICHES_CH:
        for tech_q, _ in _TECH_INDICATORS:
            dorks.add(f'{tech_q} {niche_q} {SITE}')

    # Secteurs FR/DE/IT × indicateurs techniques
    for sect in SECT_FR + SECT_DE + SECT_IT:
        for tech_q, _ in _TECH_INDICATORS:
            dorks.add(f'{tech_q} {sect} {SITE}')

    return sorted(dorks)


def main():
    print("Génération des dorks…")
    dorks = generate()
    print(f"Total généré : {len(dorks)} dorks uniques")

    out = Path("dorks_full.txt")
    out.write_text('\n'.join(dorks), encoding='utf-8')
    print(f"Sauvegardé dans : {out}")


if __name__ == "__main__":
    main()
