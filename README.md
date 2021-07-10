## 2021 Project 2

![](logo.png)

Ερωτήσεις:

1. Πού βρίσκεται ο Γιώργος;
1. Ποιος έκλεψε τα αρχεία του "Plan X";
1. Πού βρίσκονται τα αρχεία του "Plan X";
1. Ποια είναι τα results του "Plan Y";
1. Ποιο είναι το code του "Plan Z";




#### Παρατηρήσεις

- Οι ίδιες ομάδες με την εργασία 1
- Εγγραφή στο github: https://classroom.github.com/g/jlkOQHdH 
- Μόλις ολοκληρώσετε κάθε βήμα στέλνετε claim στο ys13@chatzi.org
- Για τα βήματα 3-5 απαιτείται να γράψετε ένα πρόγραμμα που να αυτοματοποιεί την εύρεση της λύσης.
  Μπορείτε να χρησιμοποιήσετε ό,τι γλώσσα προγραμματισμού θέλετε, αλλά θα πρέπει να μπορώ να το τρέξω
  σε Ubuntu 20.04 χρησιμοποιώντας software που είναι διαθέσιμο στο Ubuntu. Θα πρέπει επίσης
  να φτιάξετε ένα script `run.sh` που εκτελεί το πρόγραμμα με ό,τι παραμέτρους χρειάζονται.
- Επίσης γράφετε report στο README.md με τα βήματα που ακολουθήσατε, και το κάνετε commit μαζί με οποιοδήποτε κώδικα χρησιμοποιήσατε
- Βαθμολογία
    - Η δυσκολία στα βήματα αυξάνεται απότομα.
    - Για ό,τι δεν ολοκληρώσετε περιγράψτε (και υλοποιήστε στο πρόγραμμα) την πρόοδό σας και πώς θα μπορούσατε να συνεχίσετε.
    - Με τα πρώτα 2 βήματα παίρνετε 5 στο μάθημα (αν έχετε πάει καλά στην εργασία 1)
    - Με τα 3-5 φτάνετε μέχρι το 10 (δεν υπάρχει γραπτή εξέταση)
    - Για τους μεταπτυχιακούς τα 3-5 είναι προαιρετικά. ΔΕΝ αντικαθιστούν το project
     (αλλά μπορούν να λειτουργήσουν προσθετικά στο βαθμό της εργασίας 1)
    - Για τα βήματα 3-5 μπορεί να γίνει προφορική εξέταση
- Timeline
    - Την πρώτη εβδομάδα δεν υπάρχουν hints
    - 11/6: αρχίζουν τα hints για τα βήματα 1,2
    - 16/6: deadline για τα βήματα 1,2
    - Για τα βήματα 3-5 δίνονται hints μόνο σε όσους ζητήσουν (με μικρό penalty)
    - 11/7: deadline για τα βήματα 3-5
- Η ταχύτητα των λύσεων (και ο αριθμός hints που έχουν δοθεί) μετράει στο βαθμό
(ειδικά για τα βήματα 1,2)

- __Οχι spoilers__
- __Οχι DoS__ (ή μαζικά requests, δε χρειάζεται
κάτι τέτοιο)

## Report

1. Πού βρίσκεται ο Γιώργος;

Για να βρούμε τον Γιώργο ξεκινήσαμε την αναζήτηση μας πληκτρολογώντας το onion site που βρίσκεται στην φωτογραφία της εκφώνησης (2bx6yarg76ryzjdpegl5l76skdlb4vvxwjxpipq4nhz3xnjjh3jo6qyd.onion). Σύντομα παρατηρήσαμε ότι το visitor number στην σελίδα έχει κάποια ιδιαιτερότητα. Συγκεκριμένα ο αριθμός του επισκέπτη καθορίζεται από το cookie που είναι encoded σε base64. Στην αρχή δεν μας φάνηκε χρήσιμο οπότε το αφήσαμε στην άκρη.

Στην συνέχεια ανοίξαμε τον πηγαίο κώδικα της σελίδας και αξιοποιήσαμε το hint με το link που ήταν στα σχόλια (https://blog.0day.rocks/securing-a-web-hidden-service-89d935ba1c1d). Από το link μάθαμε ότι προσθέτοντας στο URL: /server-info μπορούμε να έχουμε πρόσβαση στα internal settings του site. Από εκεί είδαμε ότι υπάρχει και μια άλλη σελίδα (flffeyo7q6zllfse2sgwh7i5b5apn73g6upedyihqvaarhq5wrkkn7ad.onion) η οποία λειτουργεί ως προσωπική σελίδα για τους admins του πρώτου site.

Μετά μάθαμε ότι γενικά αρκετά websites χρησιμοποιούν ένα robots.txt αρχείο για να αποκλείσουν την πρόσβαση σε συγκεκριμένες σελίδες από web crawlers. Αφού βρήκαμε λοιπόν το σχετικό αρχείο, παρατηρήσαμε την αναφορά στα .phps αρχεία. Οπότε δοκιμάσαμε να γράψουμε την κατάληξη .phps για το access.php αρχείο όπου γίνεται ο έλεγχος για την πρόσβαση στο personal site. Εκεί λοιπόν βρήκαμε το source code του access.php. Βρήκαμε λοιπόν την μεταβλητή desired με βάση τα hints που υπήρχαν στα σχόλια (σχετικός κώδικας στο Secret.java αρχείο του φακέλου george_files), η οποία είχε την τιμή 1337 και με το απαραίτητο padding βρήκαμε τελικά ότι ο επιθυμητός χρήστης είναι ο 0001337. Μετά για τον κωδικό δώσαμε βάση στο γεγονός ότι χρησιμοποιείται η συνάρτηση strcmp για την εγκυρότητα του κωδικού. Αναζητήσαμε λοιπόν τρόπους για να κάνουμε exploit την συνάρτηση να επιστρέψει 0. Βρήκαμε λοιπόν ότι βάζοντας έναν πίνακα ως input (πχ: password[]=a) η strcmp επιστρέφει 0 και άρα περνάει ο έλεγχος.

Από εκεί λοιπόν μπήκαμε στο προσωπικό ιστολόγιο της Υβόννης (flffeyo7q6zllfse2sgwh7i5b5apn73g6upedyihqvaarhq5wrkkn7ad.onion/blogposts7589109238/) και αναλύσαμε τα diary entries. Το δεύτερο entry φαινόταν να αναφέρεται στο Plan X του δεύτερου ερωτήματος, οπότε το αφήσαμε στην άκρη. Δοκιμάσαμε να ελέγξουμε για πιθανά directory listings του φακέλου /blogposts7589109238/blogposts/ και έτσι ανακαλύψαμε την σελίδα post3.html. Εκεί λοιπόν βρήκαμε το hint για τον Γιώργο και αμέσως θυμηθήκαμε το cookie-based hint που είχαμε βρει στην αρχή.

Αφου λοιπόν μετατρέψαμε τον αριθμό 834472 σε sha-256 και αμέσως μετά τον συνδυασμό του αριθμόυ και του hash σε base64 encoding ενημερώσαμε το cookie από το Fixers site με την σωστή τιμή και έτσι βρήκαμε την σελίδα για τα backup αρχεία.

Κατεβάσαμε λοιπόν από την σελίδα 2bx6yarg76ryzjdpegl5l76skdlb4vvxwjxpipq4nhz3xnjjh3jo6qyd.onion/sekritbackup1843/ τα .gpg αρχεία και εστιάσαμε στο αρχείο notes.txt για το πως να τα κάνουμε decrypt. Googlάροντας την λέξη ropsten είδαμε ότι χρησιμοποιείται στο blockchain του Ethereum crypto. Πηγαίνοντας λοιπόν στην σελίδα https://ropsten.etherscan.io/ και τοποθετώντας το hash που είχε το αρχείο notes.txt πήραμε την λέξη bigtent, κοιτώντας τα σχόλια του transaction. Άρα υποψιαστήκαμε ότι πιθανότατα αυτό είναι το secret string από το key που θέλουμε. Εκτελώντας λοιπόν μια brute force μέθοδο (την οποία μπορείτε να δείτε στο decrypt.py αρχείο του φακέλου george_files) παρατηρήσαμε ότι φαίνεται να γίνεται προσπάθεια για decrypt με την ημερομηνία: 2021-01-04. Αφού αλλάξαμε λίγο την σύνταξη για την decrypt εντολή πήραμε λοιπόν τα decrypted αρχεία.

Στην συνέχεια μελετήσαμε το signal.log αρχείο και καταλάβαμε ότι το επόμενο βήμα θα είναι σε κάποιο git repo. Το σχετικό repo το βρήκαμε ανοίγωντας το firefox.log αρχείο (όχι με ιδιαίτερη ευκολία). Ψάχνοντας για κάτι διαφορετικό από το wiki link του Conversation, με search and replace βρήκαμε το επιθημητό repo: https://github.com/asn-d6/tor. Προσθέτοντας και το commit: 4ec3bbea5172e13552d47ff95e02230e6dc99692 βρήκαμε τα σχόλια για το επόμενο βήμα.

Οι παραμέτροι στα σχόλια μας θύμησαν τον RSA αλγόριθμο κρυπτογράφησης οπότε ανοίξαμε τις διαφάνειες του μαθήματος για περαιτέρω. Αφού βρήκαμε τους πρώτους αριθμούς που χρειαζόμασταν (με την χρήση του prime_finder.py του φακέλου george_files) και τον παράγοντα e^-1 από το site: https://www.dcode.fr/modular-inverse κάναμε decode τους αριθμούς Ε(x) και Ε(y) με την βοήθεια του site: https://www.dcode.fr/rsa-cipher. Έτσι πήραμε τους αριθμούς 306 για το x και 3537 για το y. Εν τέλη, από το link: aqwlvm4ms72zriryeunpo3uk7myqjvatba4ikl3wy6etdrrblbezlfqd.onion/30637353063735.txt, βρήκαμε τον Γιώργο στην τοποθεσία Gilman's Point στο Kilimanjaro, Tanzania. 

2. Ποιος έκλεψε τα αρχεία του "Plan X";

Επιστρέψαμε λοιπόν στο Blog entry #2 της Υβόννης και εκεί είδαμε το που μπορούμε να βρούμε τον source code για τον Plan X server (zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion). Ανοίξαμε το chatziko/pico στο Github και το κάναμε clone και στην συνέχεια make για να δούμε αν θα γίνει τίποτα ενδιαφέρον αν προσπαθήσουμε να τον εγκαταστήσουμε στον δικό μας υπολογιστή.

Εκεί παρατηρήσαμε το warning για το format string parameter. Αναζητήσαμε λοιπόν τρόπους για τον αν μπορεί να γίνει κάπως exploit με το format string. Αφού βρήκαμε κάποια πολύ βοηθητικά links (ιδιαίτερη αναφορά σε https://owasp.org/www-community/attacks/Format_string_attack και https://cs155.stanford.edu/papers/formatstring-1.2.pdf) δοκιμάσαμε ως user input να δώσουμε κάτι της μορφής %08x.%08x.%08x.%08x.%08x%s%s έτσι ώστε να πάρουμε κάποιους παραμέτρους από την στοίβα σε δεκαεξαδική μορφή και ταυτόχρονα να τους μετατρέψουμε σε string (με το %s). Έτσι στο 'Invalid user: ' string είδαμε το πρώτο entry του πίνακα users. Από εκεί βρήκαμε το username: admin και το md5'd password το περάσαμε από ένα md5 cracker (https://crackstation.net/) και πήραμε την τιμή: bob's your uncle.

Εν τέλη, μάθαμε ότι τα αρχεία του Plan X τα είχαν κλέψει οι επίδοξοι hackers με όνομα 5l0ppy 8uff00n5 και ευθημήσαμε γιατί η defaced σελίδα μας θύμισε την σελίδα που είχαμε δει στην 1η Απριλίου του μαθήματος μας (την οποία ένα μέλος από εμάς είχε προτείνει ως easter egg :)). Μετά βέβαια, προσγειωθήκαμε γιατί θυμηθήκαμε ότι το 3ο ερώτημα απαιτεί παραπάνω effort από όσα είχαμε δει μέχρι τώρα...

3. Πού βρίσκονται τα αρχεία του "Plan X";

Εστιάσαμε αρχικά την προσοχή μας στο πως δέχεται input η defaced σελίδα. Με τα network tools παρατηρήσαμε ότι δίνοντας input από την φόρμα που παρέχεται δεν μπορούμε να ελέγξουμε ιδιαίτερα αυτό που δίνουμε έτσι ώστε να πραγματοποίησουμε κάποιο attack. Μετά ψάξαμε για εναλλακτικούς τρόπους να στείλουμε input και δώσαμε βάση στην εντολή curl. Είδαμε ότι μπορούμε να τροποποίησουμε το μέγεθος του payload που δίνεται ως input με την χρήση της παραμέτρου: -H 'Content-Length: <size>'. Συγκεκριμένα, δίνοντας -H 'Content-Length: 0', ο πίνακας post_data που αποθηκεύει το input καταλήγει να έχει μία διαθέσιμη θέση (επειδή όταν ορίζεται ο πίνακας ως μέγεθος του δίνεται το payload_size + 1).

Παίζοντας με την curl ανακαλύψαμε και τις εξής παραμέτρους που ήταν απαραίτητες για να εκτελέσουμε buffer overflow attack: --socks5-hostname localhost:9050 το οποίο απαιτείται για την σύνδεση με το Tor network, -X POST -i γιατί οκ... ποστάρουμε data, -H 'Authorization: Basic YWRtaW46Ym9iJ3MgeW91ciB1bmNsZQ==' οπού εδώ κάνουμε authorize το αίτημα μας χρησιμοποιώντας το 'admin:bob's your uncle' σε Base64 encoded μορφή και τέλος: --data-binary @- μιας και τα δεδομένα τα οποία θα στείλουμε θέλουμε να είναι σε binary μορφή. Τα δεδομένα (attack string) παράγονται με ενα python script και δίνονται με pipe στην curl (περισσότερα για αυτό, παρακάτω). Όλα τα αίτηματα που δοκιμάσαμε και εκτελέσαμε έγιναν πάνω στο URL: zwt6vcp6d5tao7tbe3je6a2q4pwdfqli62ekuhjo55c7pqlet3brutqd.onion/ultimate.html.

Ανακαλύψαμε λοιπόν έναν τρόπο για να κάνουμε buffer overflow (χρησιμοποιώντας ως buffer τον πίνακα post_data της συνάρτησης post_param), οπότε μετά σκεφτήκαμε το τι input μπορούμε να δώσουμε για να πάρουμε πίσω τα αρχεία του Plan X. Σκεφτήκαμε δύο βασικές τακτικές. Η πρώτη ήταν να ανοίξουμε με κάποιον τρόπο το admin_pwd αρχείο που υποτίθεται είχε τους επιθυμητούς κωδικούς. Σύντομα αφήσαμε αυτήν την ιδέα γιατί δεν είδαμε κάποιον προφανή τρόπο να πάρουμε τα contents αυτού του αρχείου, τουλάχιστον όχι σε αυτήν την φάση. Η δεύτερη ιδέα ήταν να καλέσουμε με κάποιον τρόπο την συνάρτηση serve_ultimate μιας και αυτή μας επιστρέφει το ultimate.html αρχείο που θέλαμε.

Αναζητήσαμε λοιπόν τρόπους για να πάρουμε πληροφορίες για την στοίβα του προγράμματος. Τα δύο πιο σημαντικά εργαλεία που χρησιμοποιήσαμε ήταν τα εξής: το exploit του δεύτερου ερωτήματος με το format string parameter της printf και το δεύτερο η εκτελέση του server τοπικά με τον gdb. Με την χρήση του gdb είδαμε ότι μπόρουμε να πάρουμε διεύθυνσεις μνήμης από την στοίβα. Με το προηγούμενο exploit είδαμε ότι επίσης ότι μπορούμε να πάρουμε κάποιες διευθύνσεις από τον server του onion site. Χρησιμοποιώντας αυτά τα δύο εργαλεία λοιπόν καταλήξαμε πως μπορούμε να πάρουμε, αν όχι όλες, σίγουρα αρκετές πληροφορίες που χρειαζόμασταν από την στοίβα. Εκτελώντας τον server τοπικά μπορούσαμε να πάρουμε offset μεταξύ διευθύνσεων και μετά προσθέταμε αυτά τα offset στις διευθύνσεις που έδινε το προηγούμενο exploit για να παίρνουμε τις διευθύνσεις που θέλαμε. Δώσαμε λοιπόν στο onion site ως input string 31 φορες το %x. και έτσι διαβάσαμε 124 bytes από τη στοίβα. Κρατώντας τις 5 τελευταίες τετράδες(hex bytes) είχαμε στη διαθεσή μας το canary και το return address της check_auth.

Ψάχνοντας λοιπόν τρόπους να εκτελέσουμε την serve_ultimate, είδαμε τα περιεχόμενα που υπάρχουν στην στοίβα κατά την εκτέλεση της συνάρτησης post_param, με την βοήθεια του gdb. Εκεί παρατηρήσαμε σε ακριβώς ποιο σημείο βρίσκεται το return address της συνάρτησης (80 bytes μετά από τον buffer). Σκεφτήκαμε λοιπόν ότι κάνοντας overwrite την διεύθυνση αυτή με την διεύθυνση της serve_ultimate θα μπορέσουμε να την καλέσουμε. Βρήκαμε λοιπόν τη διεύθυνση της κλήσης της συνάρτησης serve_ultimate, κάνοντας disassemble και έπειτα βρήκαμε το offset από το return address της check_auth. Οπότε βρήκαμε έτσι την επιθυμητή return address, αλλά αυτό δεν ήταν αρκετό. Επρέπε να τοποθετήσουμε κάποιες ακόμη τιμές από το σημείο όπου ξεκινάει ο buffer μέχρι το σημείο όπου τοποθετείται η serve_ultimate. Αρχικά μια σημαντική παρατηρήση που κάναμε καθώς πέρναμε πληροφορίες από το format string parameter exploit, είναι ότι λίγο πριν το return address είδαμε μια διεύθυνση που άλλαζε κατά εκτελέσεις, η οποία καταλάβαμε ότι είναι το stack canary που χρησιμοποιείται για την αποτροπή εκτελέσης malicious κώδικα μέσω buffer overflow. Οπότε καταλάβαμε ότι πρέπει να δώσουμε και αυτό στο payload που στέλνουμε. 

Βέβαια είδαμε ότι το canary τελειώνει πάντα σε '00', κάτι το οποίο δυσκόλευε την δημιουργία του payload μιας και η strcpy τερματίζει με το '\0'. Παρατηρώντας όμως τον κώδικα της post_param είδαμε το εξής: Μετά τον ορισμό του buffer εκτελείται ένα for loop όπου παίρνει τον buffer και προσθέτει το μηδενικό σε σημεία όπου υπάρχουν '&' ή '=' (έτσι ώστε να ξεχωρίσει τα string του input). Εκεί λοιπόν σκεφτήκαμε ότι μπορούμε να αντικαταστήσουμε τα μηδενικά που υπάρχουν ήδη στο canary με το ascii του '&' (όπου είναι το 26). Χρησιμοποιώντας τις ίδιες τεχνικές για να πάρουμε το offset της serve_ultimate πήραμε την διεύθυνση του canary. Έτσι κατά την εκτέλεση του προγράμματος σκεφτήκαμε ότι θα έχουμε να επαναλαμβάνονται οι διευθύνσεις του canary μας, έτσι ώστε να πάει το for loop και να τοποθετήσει το 0 στο canary μας. Μετά από αυτό θα τοποθετούσαμε το canary για να ξεπεράσουμε το protection και στο τέλος την διεύθυνση της serve_ultimate.

Συγκεκριμένα λοιπόν, το τελικό μας attack string περιείχε τα εξής: 15 φορές την διεύθυνση του canary, 4 φορές το ίδιο το canary (1 ήταν η απαραίτητη απλά μπήκε κάποιες επιπλέον για να κάνουμε overwrite data μέχρι το return address) και στο τέλος βάλαμε την διεύθυνση κλήσης της server_ultimate. Έτσι καταφέραμε να κάνουμε buffer overflow και πήραμε πίσω το ultimate.html αρχείο που θέλαμε. Οπότε από εκεί είδαμε ότι τα αρχεία του Plan X βρίσκονται στο path: /var/backup/backup.log.

Το αρχείο request_x.py στον φάκελο Plan_X_files αυτοματοποίει την διαδικασία εύρεσης των επιθυμητών τιμών. Εκτελούμε αρχικά ένα request όπου φανερώνονται οι αρχικές πληροφορίες που θέλουμε, δηλαδή το return address, ο ebp και το canary. Από αυτά, και με τα offset που γνωρίζουμε από το gdb, παίρνουμε την διεύθυνση της serve_ultimate και του canary. Στην συνέχεια κάνουμε reverse ανά δύο bytes τις τιμές αυτές, μιας και λόγω του little endianness έτσι μόνο μπορούμε να κάνουμε overwrite διευθύνσεις από την στοίβα. Τέλος χτίζουμε το επιθυμητό attack string. Το run_x.sh αρχείο από τον ίδιο φάκελο εκτέλει το python script για να πάρει αυτές τις πληροφορίες και στην συνέχεια εκτελεί την curl με το malicious input που χρειάζεται για την πρόσβαση στο ultimate.html.

Για να τρέξει το συγκεκριμένο attack, αλλά και τα επόμενα χρειάζεται να έχουν εγκατασταθεί οι εξής βιβλιοθήκες:

*curl (from version 7.66.0 and on you need --http0.9 flag)*

For python:

*requests (pip install requests)*

*requests_tor (pip install requests_tor)*

4. Ποια είναι τα results του "Plan Y";

Αναλύοντας τις πληροφορίες που μας έδινε το ultimate.html, είδαμε το code tmmt8pN_lj4 και το αναζητήσαμε στο Google μήπως μας δώσει κάτι σημαντικό. Είδαμε ότι αυτό είναι μέρος του YouTube URL από το βίντεο όπου οι HackItOrDITrying είχαν χακάρει την αντίπαλη τους ομάδα στην πρώτη εργασία και ευθημήσαμε μιας και θυμηθηκάμε έτσι τις παλιές καλές εποχές. Δεν μας φάνηκε βέβαια χρήσιμο για το ερώτημα 4 οπότε εστιάσαμε αλλού.

Μιας και είχαμε έτοιμο το path του αρχείου που θέλουμε (/var/backup/backup.log) ψάξαμε να βρούμε μήπως υπάρχει τρόπος να το ανοίξουμε κάπως. Είδαμε ότι η συνάρτηση send_file κάνει ακριβώς αυτό και μιας είχαμε ήδη τρόπο για να κάνουμε buffer overflow θεωρήσαμε ότι αρκεί να καλέσουμε την send_file με το όρισμα που θέλουμε, αντί για την serve_ultimate που καλούσαμε στο ερώτημα 3. Χρησιμοποιώντας τις ίδιες τεχνικές από το προηγούμενο ερώτημα βρήκαμε το offset και την διεύθυνση της send_file. Στην συνέχεια πήραμε επίσης το hex format του path που θέλουμε και τοποθετήσαμε αυτό στην αρχή του buffer, συμπληρώνοντας με κάποια '26', προκείμενου να ευθυγραμμιστεί το string (και τα 26 όπως είπαμε και για το ερώτημα 3 θα αντικαταστιθούν από το 0 στο for loop). Επίσης χρειάστηκε να βρούμε και την διεύθυνση της αρχής του buffer μιας και η send_file θα χρησιμοποιήσει αυτό σαν όρισμα. Έτσι το attack string μας για να πάρουμε το backup.log είχε: το path του αρχείου σε hex format, (60 - len(text_payload_1))/4 = 9 φορές την διεύθυνση του buffer, το address της send_file και 2 φόρες το buffer address, καθώς παρατηρήσαμε ότι από εκεί παίρνει το όρισμα της η send_file.

Εκτελώντας το attack πήραμε τα περιεχόμενα του backup.log, που είναι τα περιεχόμενα του φακέλου backup. Στην συνέχεια, εκτελέσαμε ένα ανάλογο attack αλλά με το index.html σαν όρισμα. Από εκεί καταλάβαμε ότι η απάντηση στο Plan Y βρίσκεται στο z.log αρχείο. Εκτελέσαμε λοιπόν ένα ανάλογο attack με το z.log ως όρισμα και είδαμε ότι η απάντηση για τα αποτέλεσμα του Plan Y είναι η σταθερά: 41.998427123123. (Τα υπόλοιπα αρχεία διαπιστώσαμε αργότερα ότι ήταν easter eggs)

Το request_y.py αρχείο στα Plan_Y_files εκτελεί, όπως και στο προηγούμενο request.py, όλες τις απαραίτητες ενέργειες για το χτήσιμο του attack string που μας δίνει πίσω το z.log αρχείο (είτε με τον κατάλληλο αποσχολιασμό, τα αρχεία backup.log και index.html). Ομοίως το run_y.sh εκτελεί το επιθημητό attack.

5. Ποιο είναι το code του "Plan Z";

Στο αρχείο z.log είδαμε ότι παρέχονται οι πληροφορίες που αφορούσαν το επόμενο και τελευταίο ερώτημα για το Plan Z. Το επιθυμητό code μας το έδινε η επόμενη κίνηση από αυτές που είχαμε ήδη καθώς και η IP του μηχανήματος που τρέχει τον server. Γρήγορα καταλάβαμε ότι οι κινήσεις που είχαν δοθεί αφορούσαν ένα παιχνίδι σκάκι. Σκεφτήκαμε δίασημα παιχνίδια από σκάκι και μας ήρθαν στο μυαλό τα παιχνίδια του Kasparov με τον Deep Blue. Βρήκαμε λοιπόν ότι οι κινήσεις είναι από τελευταίο παιχνίδι που είχαν παίξει (https://en.wikipedia.org/wiki/Deep_Blue_versus_Garry_Kasparov#Game_6_2) και έτσι βρήκαμε την επόμενη κίνηση: c4 1–0. 

Μετά για να βρούμε την public IP σκεφτήκαμε ότι υπάρχουν διάφορα site για αυτόν τον σκόπο όπως το: checkip.dyndns.org. Επίσης με την curl μπορούμε να πάρουμε το response αυτής της σελίδας και να το δούμε στο terminal. Θυμηθληκαμε επίσης, πως ένας τρόπος για να εκτελέσεις linux εντολές σε ενα C πρόγραμμα είναι η συνάρτηση system. Οπότε καταλήξαμε πως για να πάρουμε την public IP πρέπει να κάνουμε ακόμη ένα buffer overflow αυτή την φορά καλώντας την system με το επιθυμητό όρισμα, δηλαδή: "curl checkip.dyndns.org" (το οποίο overflow συγκεκριμένα αποκαλείται και return-to-libc attack μιας και αξιοποιούμε την system της libc).

Σύντομα διαπιστώσαμε πως αυτό δεν ήταν μια ενέργεια στο ίδιο level ευκολίας όπως τα buffer overflows που εκτελέσαμε στα ερωτήματα 3 και 4. Ο πιο μεγάλος μας αντίπαλος ήταν φυσικά το ASLR. Χαρή σε αυτό τα offset που παίρναμε για να βρούμε την system ήταν διαφορετικά σε κάθε εκτέλεση πιθανού attack. Προσπαθήσαμε να πάρουμε την system με διαφόρα starting points. Κάποιες προσπάθειες μας αξιοποιούσαν την διεύθυνση της __libc_start_main, όπως το να πάρουμε το offset της system από αυτήν ή να την χρησιμοποιήσουμε για να πάρουμε το base address της libc και να βρούμε offset της system από αυτήν. Αφού όλα αυτά κατέληξαν σε αποτυχία παρατηρήσαμε ότι αριστερά και δεξιά από το canary που παίρνουμε από την broken printf του ερώτηματος 2 βρίσκονται διευθύνσεις στον ίδιο χώρο διευθύνσεων με τη system, άρα κάτα πάσα πιθανότητα ανήκουν στην libc.

Στην αρχή σκεφτήκαμε πάλι να πάρουμε την system με offset από αυτές τις διευθύνσεις. Λόγω ASLR δεν γινόταν κάτι τέτοιο όμως. Τελικά όμως σκεφτήκαμε το εξής: Το ASLR μετακινεί τις διευθύνσεις ανά execution. Αν όμως εμείς πάρουμε την διαφορά από τη διευθυνση της libc που είναι στο onion site με την αντίστοιχη που παίρνουμε στο τοπίκο μας pico και προσθέσουμε αυτήν την διαφορά στην διεύθυνση από την system μιας τοπικής εκτέλεσης του server, τότε θα έχουμε πάρει την αντίστοιχη system από τον onion server. Αυτό θα δουλέψει καθώς οι μεταξύ τους αποστάσεις μένουν σταθερές ακόμα και με το ASLR.

Η τελική μας ιδέα ήταν λοιπόν: Να προσθέσουμε αρχικά ένα print στον τοπικό μας server για πάρουμε την system (π.χ. fprintf(stderr, "%p\n", &system); πριν την κλήση της serve_forever στην main). Μετά εκτελούμε τον server, παίρνουμε την διεύθυνση της system και την κρατάμε. Αφήνουμε ανοιχτό τον server και στην συνέχεια κάνουμε 2 request, ένα στο τοπικό pico και ένα στο onion site. Από αυτά τα request παίρνουμε τη διεύθυνση που βρίσκεται αριστερά από το canary, την μία φορά από τον τοπικό server και την άλλη από το onion (το δεξιά δεν λειτουργούσε μάλλον διότι βρίσκεται σε διαφορετικό σημείο της libc. Επίσης για κάποιον λόγο το ένα από τα δύο μέλη της ομάδας είχε πάντα 0 σε αυτό το σημείο (το αριστερό) στην τοπική εκτελέση του server. Για αυτόν τον λόγο το τελικό attack λειτουργεί σε ένα από τα δύο μέλη της ομάδας). Παίρνουμε την διαφορά μεταξύ αυτών των δύο και στο τέλος προσθέτουμε την διαφορά στην system που πήραμε από την τοπική εκτέλεση του server για να πάρουμε την system που θέλουμε. Στο attack string που χτίζουμε βάλαμε λοιπόν: 15 φορές το buffer address, 4 φορές το canary, το address της system, 2 φορές το address του ορίσματος και τέλος το ίδιο το όρισμα της system. Μετά από τα πολλά καταφέραμε να εκτελέσουμε αυτήν την επίθεση και να πάρουμε την public IP του μηχανήματος που τρέχει τον server, η οποία είναι η 54.159.81.179.

To αρχείο request_z.py στον φάκελο Plan_Z_files αυτοματοποίει μέρος από την διαδικασία που μόλις περιγράψαμε. Ο λόγος που δεν μπορούμε να αυτοματοποιήσουμε ολοκλήρη την διαδικασία είναι γιατί πρέπει να πάρουμε και να δώσουμε 'καρφωτά' την διεύθυνση της τοπικής system. Επίσης πρέπει να τρέχουμε και τον τοπικό server για να εκτελεστεί η επίθεση. Ωστόσο όλη η υπόλοιπη διαδικασία καλύπτεται από το python script. Αφού δοθεί η τοπική system στο request_z.py, η τελική επίθεση μπορεί να εκτελεστεί από το run_z.sh.

Τέλος, παρέχουμε μια ελαφρώς τροποποιημένη version της main.c του pico, όπου απαντάει σε get request στο /system με τη διεύθυνση της system function. Θεωρήσαμε ότι αυτός είναι ένας πιο ορθός τρόπος για να πάρουμε την τοπική system, σε σχέση με τον προηγούμενο τρόπο με την fprintf. Άρα για αναπαραγωγή του attack πρέπει απλώς να γίνει ενα get request στο /system και έτσι έχουμε την τοπική διεύθυνση της system που είναι απαραίτητη για το attack. Έχουμε αφήσει και την επιλογή να γίνει αυτό το request αυτόματα από το request_z.py σε κατάλληλα σχολιασμένες γραμμές. Επειδή δεν ξέραμε κατά πόσο είναι θεμιτό το request_z.py να αξιοποίει μια edited έκδοση του τοπικού pico server, επιλέξαμε να το αφήσουμε σαν επιλογή.

SnowdenFanboys signing out!
(PS: Sending out our support to our exiled hero in Moscow)


