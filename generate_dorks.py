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


# ── Niches 10k-100k users — indicateur technique + secteur ────
# But : sites avec vraie app web (params PHP, login, search, catalog)
# Pas de static pages — combinaison niche + vecteur technique obligatoire

# Paramètres GET injectables par niche
_PARAMS = [
    'inurl:"?id="',
    'inurl:"?cat="',
    'inurl:"?page="',
    'inurl:"?article="',
    'inurl:"?ref="',
    'inurl:"?search="',
]

# Indicateurs de vraie app (login, inscription, catalogue)
_APP_INDICATORS = [
    'inurl:"login.php"',
    'inurl:"inscription.php"',
    'inurl:"register.php"',
    'inurl:"search.php"',
    'inurl:"catalogue.php"',
    'inurl:"annonce.php"',
    'inurl:"reservation.php"',
    'inurl:"booking.php"',
    'inurl:"produit.php"',
    'inurl:"fiche.php"',
    'inurl:"detail.php"',
    'inurl:"member.php"',
    'inurl:"profil.php"',
    'inurl:"account.php"',
    'inurl:"espace-membre"',
]

# Niches FR ciblées 10k-100k (pas trop larges, pas trop étroites)
_NICHES_FR = [
    '"association sportive"',
    '"club de sport"',
    '"école de musique"',
    '"cours de danse"',
    '"école de yoga"',
    '"cabinet médical"',
    '"cabinet dentaire"',
    '"cabinet vétérinaire"',
    '"pharmacie"',
    '"ostéopathe"',
    '"physiothérapeute"',
    '"cabinet de kinésithérapie"',
    '"traiteur"',
    '"salle de réception"',
    '"domaine viticole"',
    '"cave viticole"',
    '"fromagerie"',
    '"boulangerie artisanale"',
    '"chocolatier"',
    '"épicerie fine"',
    '"gîte rural"',
    '"chambre d\'hôtes"',
    '"camping"',
    '"club de golf"',
    '"club de tennis"',
    '"école de ski"',
    '"location de vacances"',
    '"agence immobilière"',
    '"agence de voyage"',
    '"agence événementielle"',
    '"auto-école"',
    '"centre de formation"',
    '"soutien scolaire"',
    '"cours particuliers"',
    '"fiduciaire"',
    '"expert-comptable"',
    '"cabinet d\'avocat"',
    '"étude notariale"',
    '"courtier en assurance"',
    '"club de randonnée"',
    '"association culturelle"',
    '"maison de retraite"',
    '"résidence seniors"',
    '"service de garde"',
    '"crèche"',
    '"librairie"',
    '"galerie d\'art"',
    '"salon de coiffure"',
    '"spa"',
    '"centre de bien-être"',
    '"clinique esthétique"',
    '"pépinière"',
    '"jardinerie"',
    '"animalerie"',
    '"pension pour chiens"',
]

# Niches DE ciblées 10k-100k
_NICHES_DE = [
    '"Sportverein"',
    '"Musikschule"',
    '"Tanzschule"',
    '"Yoga-Schule"',
    '"Zahnarztpraxis"',
    '"Tierarztpraxis"',
    '"Apotheke"',
    '"Physiotherapie"',
    '"Osteopathie"',
    '"Weingut"',
    '"Käserei"',
    '"Bäckerei"',
    '"Konditorei"',
    '"Ferienhaus"',
    '"Ferienwohnung"',
    '"Campingplatz"',
    '"Tennisclub"',
    '"Golfclub"',
    '"Skischule"',
    '"Immobilienmakler"',
    '"Autoschule"',
    '"Nachhilfeschule"',
    '"Berufsschule"',
    '"Treuhandbüro"',
    '"Anwaltskanzlei"',
    '"Versicherungsmakler"',
    '"Wanderclub"',
    '"Kulturverein"',
    '"Altersheim"',
    '"Kinderbetreuung"',
    '"Buchhandlung"',
    '"Kunstgalerie"',
    '"Coiffeursalon"',
    '"Wellness-Center"',
    '"Tierpension"',
    '"Reisebüro"',
    '"Eventlocation"',
    '"Partyservice"',
]

# Niches IT ciblées 10k-100k
_NICHES_IT = [
    '"studio medico"',
    '"studio dentistico"',
    '"farmacia"',
    '"fisioterapia"',
    '"cantina vinicola"',
    '"caseificio"',
    '"panificio"',
    '"agriturismo"',
    '"bed and breakfast"',
    '"tennis club"',
    '"scuola di danza"',
    '"agenzia immobiliare"',
    '"autoscuola"',
    '"studio legale"',
    '"associazione sportiva"',
    '"centro benessere"',
]


def generate():
    dorks = set()

    # Dorks techniques — forcés site:.ch
    for d in TECH_DORKS:
        if SITE not in d:
            dorks.add(f'{d} {SITE}')
        else:
            dorks.add(d)

    # Dorks scanner-spécifiques — forcés site:.ch
    for d in SCANNER_DORKS:
        if SITE not in d:
            dorks.add(f'{d} {SITE}')
        else:
            dorks.add(d)

    # ── Niches 10k-100k : niche + param GET injectable ──────────
    for niche in _NICHES_FR + _NICHES_DE + _NICHES_IT:
        for param in _PARAMS:
            dorks.add(f'{param} inurl:".php" {niche} {X}')

    # ── Niches 10k-100k : niche + indicateur app (login/catalog) ─
    for niche in _NICHES_FR:
        for ind in _APP_INDICATORS[:8]:
            dorks.add(f'{ind} {niche} {X}')
    for niche in _NICHES_DE:
        for ind in _APP_INDICATORS[:8]:
            dorks.add(f'{ind} {niche} {X}')
    for niche in _NICHES_IT:
        for ind in _APP_INDICATORS[:6]:
            dorks.add(f'{ind} {niche} {X}')

    # ── Niches 10k-100k + région (sans param, pour CMS/WP) ───────
    for niche in _NICHES_FR[:25]:
        for reg in REG_FR[:8]:
            dorks.add(f'inurl:".php" {niche} {reg} {X}')
    for niche in _NICHES_DE[:25]:
        for reg in REG_DE[:8]:
            dorks.add(f'inurl:".php" {niche} {reg} {X}')

    # ── Niches + WP (beaucoup de petits sites WP dans ces secteurs) ─
    for niche in _NICHES_FR[:20]:
        dorks.add(f'inurl:"wp-login.php" {niche} -wordpress.com {X}')
        dorks.add(f'inurl:"/wp-content/" {niche} -wordpress.com {X}')
    for niche in _NICHES_DE[:20]:
        dorks.add(f'inurl:"wp-login.php" {niche} -wordpress.com {X}')
        dorks.add(f'inurl:"/wp-content/" {niche} -wordpress.com {X}')

    # ── Ancien secteur + action (conservé, moins prioritaire) ────
    for sect in SECT_FR[:30]:
        for act in ACT_FR[:5]:
            dorks.add(f'{sect} {act} {X}')
    for sect in SECT_DE[:30]:
        for act in ACT_DE[:5]:
            dorks.add(f'{sect} {act} {X}')
    for sect in SECT_IT[:15]:
        for act in ACT_IT[:4]:
            dorks.add(f'{sect} {act} {X}')

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
