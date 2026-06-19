#!/usr/bin/env python3
"""Générateur de dorks — produit ~15k-20k dorks uniques."""
from pathlib import Path
import itertools

# ── Exclusions ─────────────────────────────────────────────────
X  = "-exemple -test -demo -admin -facebook -linkedin -instagram -youtube -wikipedia -github -twitter"
XB = "-booking -airbnb -tripadvisor -expedia -hotels.com"
XS = "-amazon -galaxus -digitec -zalando -migros -coop -manor -microspot"
XK = "-comparis -local.ch -search.ch -homegate -scout24 -tutti.ch -anibis -doctolib"

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
    'inurl:"?file=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?path=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?include=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?template=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?lang=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?language=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?dir=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?load=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?pg=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?filename=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?download=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?read=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?document=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?fichier=" inurl:".php" -github -stackoverflow -exemple',
    # RCE / command injection
    'inurl:"?cmd=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?exec=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?command=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?ping=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?execute=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?shell=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?ip=" inurl:".php" ("ping" OR "traceroute" OR "nslookup") -github',
    'inurl:"?host=" inurl:".php" ("test" OR "check" OR "verify") -github',
    'inurl:"?domain=" inurl:".php" ("check" OR "test" OR "lookup") -github',
    # SSTI
    'inurl:"?template=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?tpl=" inurl:".php" -github -stackoverflow -exemple',
    'inurl:"?skin=" inurl:".php" -github -stackoverflow -exemple',
    '"Smarty" ("formulaire" OR "devis" OR "contact") inurl:".php" -github -smarty.net',
    'inurl:"/preview" inurl:".php" -github -stackoverflow -exemple',
    # Frameworks PHP
    'inurl:"/public/index.php" -github -laravel.com -exemple',
    'inurl:"/app_dev.php" -github -symfony.com -exemple',
    '"Laravel" inurl:"login" -laravel.com -github -exemple',
    '"Symfony" inurl:"login" -symfony.com -github -exemple',
    '"Powered by CakePHP" -cakephp.org -github',
    # Frameworks Python
    'inurl:"/admin/" "Django administration" -github -djangoproject.com',
    '"DisallowedHost" "Django" -github -stackoverflow',
    '"Werkzeug Debugger" -github -stackoverflow',
    'inurl:"/__debug__/" -github -stackoverflow',
    # Erreurs d'exécution
    '"Fatal error:" "on line" -github -stackoverflow -php.net',
    '"Warning: include(" -github -stackoverflow -php.net',
    '"Warning: require(" -github -stackoverflow -php.net',
    '"failed to open stream: No such file or directory" -github -stackoverflow',
    '"open_basedir restriction in effect" -github -stackoverflow',
    '"OperationalError" "no such table" -github -stackoverflow',
    '"sqlite3.OperationalError" -github -stackoverflow',
    # SQLi supplémentaires
    '"near" "syntax error" "SQLite" -github -stackoverflow',
    '"unrecognized token" "SQLite" -github -stackoverflow',
    '"XPATH syntax error" -github -stackoverflow',
    '"Column count doesn\'t match" -github -stackoverflow',
    '"Unknown column" "in \'field list\'" -github -stackoverflow',
    '"operator does not exist" "integer" -github -stackoverflow',
    # Open redirect
    'inurl:"?redirect=" inurl:".php" -github -stackoverflow',
    'inurl:"?return=" inurl:".php" -github -stackoverflow',
    'inurl:"?next=" inurl:".php" -github -stackoverflow',
    'inurl:"?goto=" inurl:".php" -github -stackoverflow',
    'inurl:"?dest=" inurl:".php" -github -stackoverflow',
    'inurl:"?redir=" inurl:".php" -github -stackoverflow',
    'inurl:"?callback=" inurl:".php" -github -stackoverflow',
    'inurl:"?return_url=" inurl:".php" -github -stackoverflow',
    # APIs non documentées
    'inurl:"/api/users" -github -facebook -google -swagger.io',
    'inurl:"/api/admin" -github -facebook -google -swagger.io',
    'inurl:"/api/config" -github -facebook -google',
    'inurl:"/api/debug" -github -facebook -google',
    'inurl:"?format=json" inurl:".php" -github -facebook',
    'inurl:"?output=json" inurl:".php" -github -facebook',
    'inurl:"/ajax/" inurl:".php" -github -facebook -wordpress',
    # Fichiers sensibles
    'intitle:"index of" "users.sql"',
    'intitle:"index of" "accounts.sql"',
    'intitle:"index of" "passwords.sql"',
    '"DB_HOST" "DB_PASSWORD" filetype:env -github',
    '"define(\'DB_PASSWORD\'" filetype:php -github',
    # CMS plugins vulnérables
    'inurl:"/wp-content/plugins/" inurl:"?id=" -wordpress.com -github',
    'inurl:"/wp-content/plugins/revslider" -wordpress.com -github',
    'inurl:"?option=com_contact" -joomla.org',
    'inurl:"?option=com_search" -joomla.org',
    'inurl:"?q=user/login" -drupal.org -github',
    'inurl:"?q=search/node" -drupal.org -github',
]


# ── Dorks techniques ───────────────────────────────────────────
TECH_DORKS = [
    # SQLi GET params
    'inurl:"?id=" inurl:".php" -youtube -facebook -google -wikipedia -github',
    'inurl:"?cat=" inurl:".php" -youtube -facebook -google',
    'inurl:"?page=" inurl:".php" -youtube -facebook -google',
    'inurl:"?article=" inurl:".php" -youtube -facebook -google',
    'inurl:"?product=" inurl:".php" -youtube -facebook -google',
    'inurl:"?item=" inurl:".php" -youtube -facebook -google',
    'inurl:"?news=" inurl:".php" -youtube -facebook -google',
    'inurl:"?ref=" inurl:".php" -youtube -facebook -google',
    'inurl:"?user=" inurl:".php" -youtube -facebook -google',
    'inurl:"?action=" inurl:".php" -youtube -facebook -google',
    'inurl:"?p=" inurl:".php" -youtube -facebook -google',
    'inurl:"?pid=" inurl:".php" -youtube -facebook -google',
    'inurl:"?cid=" inurl:".php" -youtube -facebook -google',
    'inurl:"?nid=" inurl:".php" -youtube -facebook -google',
    'inurl:"?sid=" inurl:".php" -youtube -facebook -google',
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
    'inurl:"?id=" inurl:".asp" -youtube -facebook -google',
    'inurl:"?id=" inurl:".aspx" -youtube -facebook -google',
    'inurl:"Default.aspx?id="',
    'inurl:"page.aspx?id="',
    'inurl:"detail.aspx?id="',
    'inurl:"product.aspx?id="',
    # XSS search forms
    'inurl:"?search=" inurl:".php" -google -youtube -facebook',
    'inurl:"?q=" inurl:".php" -google -youtube -facebook -amazon',
    'inurl:"?query=" inurl:".php" -google -youtube -facebook',
    'inurl:"?keyword=" inurl:".php" -google -youtube -facebook',
    'inurl:"recherche.php" -google -youtube -facebook',
    'inurl:"search.php" -google -youtube -facebook -github',
    'intitle:"résultats de recherche" inurl:".php" -google',
    'intitle:"Suchergebnisse" inurl:".php" -google',
    'intitle:"risultati ricerca" inurl:".php" -google',
    # Auth forms
    'inurl:"login.php" -facebook -google -admin -exemple -demo',
    'inurl:"connexion.php" -facebook -google -exemple -demo',
    'inurl:"/espace-client" inurl:".php" -facebook -google',
    'inurl:"/mon-compte" inurl:".php" -facebook -google',
    'inurl:"/membre" inurl:".php" -facebook -google',
    'inurl:"signin.php" -facebook -google -exemple',
    'inurl:"authenticate.php" -facebook -google',
    'inurl:"/login" inurl:".php" -facebook -google -exemple',
    'inurl:"/connexion" inurl:".php" -facebook -google',
    'intitle:"connexion" inurl:".php" -facebook -google -admin',
    'intitle:"Anmeldung" inurl:".php" -facebook -google -admin',
    'inurl:"register.php" -facebook -google -exemple',
    'inurl:"inscription.php" -facebook -google -exemple',
    'inurl:"/register" inurl:".php" -facebook -google',
    # Admin panels
    'inurl:"/phpmyadmin" -demo -exemple -localhost',
    'inurl:"/adminer" -demo -exemple -localhost',
    'inurl:"/adminer.php" -demo -exemple',
    'inurl:"/pma/" -demo -exemple',
    'inurl:"/dbadmin/" -demo -exemple',
    'inurl:"/wp-admin" -demo -exemple -wordpress.com',
    'inurl:"/administrator" -demo -exemple -joomla.org',
    'inurl:"/admin" inurl:".php" -facebook -google -exemple -admin.ch',
    'inurl:"/backend" inurl:".php" -exemple -demo',
    'inurl:"/panel" inurl:".php" -exemple -demo',
    'inurl:"/dashboard" inurl:".php" -exemple -demo',
    'inurl:"/controlpanel" -exemple -demo',
    'inurl:"/cpanel" -exemple -demo -godaddy',
    'inurl:"/webmail" -exemple -demo',
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
    'inurl:"phpinfo.php" -exemple -github -stackoverflow',
    'inurl:"info.php" "PHP Version" -exemple -github',
    'intitle:"PHP Version" "Server API" -exemple -github',
    'inurl:"/.git" -github -gitlab -bitbucket',
    'inurl:".env" "DB_PASSWORD" -github -stackoverflow',
    'inurl:"config.php.bak" -github -exemple',
    'inurl:"dump.sql" -github -exemple',
    'inurl:"database.sql" -github -exemple',
    'inurl:"backup.sql" -github -exemple',
    'inurl:"/backup/" intitle:"index of" -github',
    'inurl:"/logs/" intitle:"index of" -github',
    # DB errors
    '"You have an error in your SQL syntax" -stackoverflow -github -w3schools',
    '"mysql_fetch_array()" -stackoverflow -github -w3schools',
    '"Warning: mysql_" -stackoverflow -github -w3schools',
    '"mysqli_fetch" "Warning" -stackoverflow -github',
    '"ORA-01756" -stackoverflow -github -oracle.com',
    '"pg_query()" "Warning" -stackoverflow -github',
    '"SQLite3::query" "Warning" -stackoverflow -github',
    '"ODBC SQL Server Driver" -stackoverflow -github',
    '"supplied argument is not a valid MySQL" -stackoverflow -github',
    '"Uncaught PDOException" -stackoverflow -github',
    '"mysql_num_rows()" "Warning" -stackoverflow -github',
    '"pg_exec()" "Warning" -stackoverflow -github',
    # API endpoints
    'inurl:"/api/v1/" -facebook -google -github -swagger.io',
    'inurl:"/api/v2/" -facebook -google -github',
    'inurl:"/api/v3/" -facebook -google -github',
    'inurl:"/rest/api/" -facebook -google -github',
    'inurl:"/swagger" -github -demo -swagger.io',
    'inurl:"/swagger-ui" -github -demo',
    'inurl:"/graphql" -facebook -github -demo -graphql.org',
    'inurl:"/api/" inurl:".php" -facebook -google -github',
    # File upload
    'inurl:"upload.php" -github -exemple -demo',
    'inurl:"uploader.php" -github -exemple',
    'inurl:"file_upload.php" -github -exemple',
    'inurl:"upload" inurl:".php" ("fichier" OR "télécharger") -github',
    'intitle:"upload" inurl:".php" -github -stackoverflow',
    # WordPress
    'inurl:"wp-login.php" -wordpress.com -exemple -demo',
    'inurl:"/wp-json/wp/v2/users" -wordpress.com -github',
    'inurl:"/wp-content/uploads/" intitle:"index of" -wordpress.com',
    'inurl:"?author=" inurl:".php" -wordpress.com -facebook',
    'inurl:"/wp-json/" -wordpress.com -github -demo',
    'inurl:"xmlrpc.php" -wordpress.com -github',
    # Joomla / CMS
    'inurl:"index.php?option=com_" -joomla.org -demo',
    'inurl:"?view=" inurl:"?layout=" inurl:".php" -joomla.org',
    'inurl:"?module=" inurl:"?func=" -exemple -demo',
    'inurl:"index.php?option=com_user" -joomla.org',
    # Intitle/inurl patterns
    'intitle:"formulaire de contact" -admin -exemple -test -facebook -linkedin',
    'intitle:"demande de devis" -admin -exemple -test -facebook',
    'intitle:"prise de rendez-vous" -admin -exemple -test -facebook',
    'intitle:"réservation en ligne" -admin -exemple -booking -airbnb',
    'intitle:"formulaire d\'inscription" -admin -exemple -test -facebook',
    'intitle:"commander en ligne" -admin -exemple -amazon -galaxus',
    'intitle:"Angebot anfordern" -admin -Beispiel -facebook',
    'intitle:"Termin buchen" -admin -Beispiel -facebook -doctolib',
    'intitle:"Anmeldung" inurl:formular -admin -Beispiel',
    'intitle:"prenota online" -admin -esempio -booking',
    'inurl:"/devis" -facebook -linkedin -admin -exemple',
    'inurl:"/inscription" -facebook -linkedin -admin -exemple',
    'inurl:"/reservation" -facebook -linkedin -admin -booking',
    'inurl:"contact.php" -facebook -linkedin -admin -wikipedia',
    'inurl:"formulaire.php" -facebook -linkedin -admin',
    'inurl:"devis.php" -facebook -linkedin -admin',
    'inurl:"kontakt.php" -admin -Beispiel -facebook',
    'inurl:"contatto.php" -admin -esempio -facebook',
    'inurl:"/rendez-vous" -facebook -linkedin -admin -doctolib',
    'inurl:"?page=contact" -facebook -linkedin -admin',
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

    # Dorks techniques (fixes)
    for d in TECH_DORKS:
        dorks.add(d)

    # Dorks scanner-spécifiques
    for d in SCANNER_DORKS:
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
