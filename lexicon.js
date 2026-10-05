/* Opaque -- word lists the leak guard reasons with.
 *
 * Kept apart from the logic so they can be read, audited and extended without
 * touching any code. Everything here is lowercase.
 */
var OpaqueLexicon = (function () {
  "use strict";

  function set(str) {
    var s = Object.create(null);
    str.split(/\s+/).forEach(function (w) { if (w) s[w] = true; });
    return s;
  }

  /* ------------------------------------------------------------ common words
   * Roughly the most frequent English words, plus the words people use when
   * they talk ABOUT a password rather than give it ("weak", "expired",
   * "stronger"). In a slot where a secret could go, one of these is almost
   * never the secret; anything else is treated as one. */
  var COMMON = set(
    // function words, pronouns, determiners, auxiliaries
    "a an the this that these those there here it its it's itself i me my mine myself we us our ours " +
    "ourselves you your yours yourself yourselves he him his himself she her hers herself they them " +
    "their theirs themselves one ones someone somebody something anyone anybody anything everyone " +
    "everybody everything no none nobody nothing each every either neither both all any some few many " +
    "much more most less least other others another such what which who whom whose whoever whatever " +
    "whichever when where why how whenever wherever however than then as so too very just only also " +
    "even still yet already again ever never always often sometimes usually really quite rather almost " +
    "enough not no yes yeah yep nope ok okay okey please thanks thank sorry hi hello hey bye dear " +
    "and or but nor if unless because since while though although whether till until after before " +
    "about above across against along among around at by down during except for from in inside into " +
    "near of off on onto out outside over past per through throughout to toward towards under underneath " +
    "up upon via with within without is am are was were be been being have has had having do does did " +
    "doing done can could may might must shall should will would ought need needs let lets let's " +
    "isn't aren't wasn't weren't don't doesn't didn't can't couldn't won't wouldn't shouldn't haven't " +
    "hasn't hadn't i'm i've i'll i'd you're you've you'll he's she's we're they're that's what's " +
    "there's here's who's how's gonna wanna gotta " +
    // everyday verbs and their common forms
    "get gets got getting gotten go goes went going gone make makes made making know knows knew known " +
    "think thinks thought thinking take takes took taken taking see sees saw seen seeing come comes came " +
    "coming want wants wanted wanting look looks looked looking use uses used using find finds found " +
    "finding give gives gave given giving tell tells told telling work works worked working call calls " +
    "called calling try tries tried trying ask asks asked asking feel feels felt feeling become becomes " +
    "became leave leaves left leaving put puts putting mean means meant keep keeps kept keeping begin " +
    "begins began begun seem seems seemed help helps helped helping show shows showed shown hear hears " +
    "heard play plays played run runs ran running move moves moved like likes liked live lives lived " +
    "believe believes believed bring brings brought happen happens happened write writes wrote written " +
    "writing provide provides provided sit sits sat stand stands stood lose loses lost losing pay pays " +
    "paid meet meets met include includes included continue continues continued set sets setting learn " +
    "learns learned learnt change changes changed changing lead leads led understand understands " +
    "understood watch watches watched follow follows followed stop stops stopped create creates created " +
    "speak speaks spoke spoken read reads reading allow allows allowed add adds added adding spend spent " +
    "grow grew grown open opens opened opening walk walked win won offer offered remember remembers " +
    "remembered forget forgets forgot forgotten love loved consider considered appear appeared buy bought " +
    "wait waiting waited serve served die died send sends sent sending expect expected build built stay " +
    "stays stayed staying fall fell cut reach reached kill remain remains remained suggest suggested " +
    "raise pass passes passed passing sell sold require requires required report reported decide decided " +
    "pull pulled enter enters entered entering type types typed typing save saves saved saving store " +
    "stored reset resets resetting update updates updated updating choose chose chosen pick picked " +
    "check checks checked checking share shares shared sharing fix fixed fixing sign signed signing " +
    "login log logged logging logout signup unlock unlocked lock locked access accessed generate " +
    "generated guess guessed hack hacked leak leaked steal stole stolen crack cracked recover recovered " +
    "confirm confirmed verify verified receive received request requested apply applied install installed " +
    "download downloaded upload uploaded click clicked press pressed delete deleted remove removed copy " +
    "copied paste pasted reuse reused rotate rotated expire expires expired expiring hide hidden mask " +
    "masked encrypt encrypted hash hashed protect protected block blocked reject rejected rejecting " +
    "accept accepted fail fails failed failing work worked break broke broken say says said tells " +
    // adjectives, including the ones used to describe passwords
    "good better best bad worse worst new old great high low big small large little long longer longest " +
    "short shorter shortest strong stronger strongest weak weaker weakest secure securer insecure safe " +
    "safer unsafe easy easier hard harder difficult simple simpler complex complicated random unique " +
    "same different similar common rare right wrong correct incorrect valid invalid real true false " +
    "important possible impossible able free full empty blank clear public private personal secret " +
    "sensitive confidential current previous next last first second third final main whole entire " +
    "sure certain likely unlikely quick fast slow early late young ready special general specific " +
    "strange normal usual typical proper basic simple standard default temporary permanent memorable " +
    "obvious guessable predictable original fine nice cool okay awesome terrible horrible happy sad " +
    "sure open closed available unavailable necessary optional required mandatory active inactive " +
    "enabled disabled visible invisible actual same above below following missing wrong funny serious " +
    "whole best worst own several various certain enough recent recently lucky favourite favorite " +
    "top bottom left right middle key major minor clean safe healthy sick ill " +
    // nouns
    "time times year years day days week weeks month months hour hours minute minutes second seconds " +
    "today tomorrow yesterday tonight morning evening night noon now later soon moment people person " +
    "man men woman women child children kid kids baby family friend friends name names thing things " +
    "way ways world life hand hands part parts place places case point group problem problems fact " +
    "question questions answer answers issue issues idea ideas home house room office school work job " +
    "business company system program programs number numbers word words line lines side end start " +
    "example information info data detail details reason result results kind sort type level form area " +
    "money price cost account accounts email emails mail message messages phone phones mobile app apps " +
    "website site page pages link links file files document documents photo photos picture pictures " +
    "text code codes key keys lock password passwords passcode pin pins otp user users username " +
    "usernames login logins id ids card cards bank banks number field fields box button screen device " +
    "devices computer laptop browser internet wifi network server database manager managers policy " +
    "policies rule rules requirement requirements character characters letter letters digit digits " +
    "symbol symbols length combination hint hints question security safety privacy protection attack " +
    "attacks hacker hackers generator vault team teams game games car cars dog dogs cat cats pet pets " +
    "book books movie movies song songs food water city country state town village street road " +
    "birthday anniversary date dates address addresses history future past present version update " +
    "updates error errors mistake message setting settings option options list lists step steps " +
    "method methods tip tips advice help support service services customer customers order orders " +
    "delivery payment payments bill bills tax loan salary report reports meeting meetings project " +
    "projects task tasks plan plans test tests exam exams class classes course courses doctor doctors " +
    "hospital medicine health body head heart mind eye eyes face voice story news article topic " +
    "language english hindi everything nothing anything something sample dummy placeholder test " +
    "stuff bit lot lots kind sort couple pair half rest beginning middle end " +
    // numbers written out, and misc
    "zero one two three four five six seven eight nine ten eleven twelve twenty thirty forty fifty " +
    "hundred thousand lakh lakhs crore crores million billion once twice first second " +
    "again everywhere anywhere somewhere nowhere else instead maybe perhaps probably actually " +
    "basically literally definitely exactly especially currently finally generally simply together " +
    "online offline via etc admin administrator root role guest owner member members"
  );

  /* The passwords everyone uses. As a value they are still the secret. */
  var COMMON_PASSWORDS = set(
    "password password1 password123 passw0rd p@ssw0rd 123456 1234567 12345678 123456789 1234567890 " +
    "qwerty qwerty123 abc123 admin admin123 letmein welcome welcome1 iloveyou monkey dragon " +
    "football cricket sunshine princess master shadow 111111 000000 123123 654321 india123 " +
    "india@123 changeme secret root toor guest test test123 default"
  );

  /* Words that follow a secret's name without being the secret. */
  var DESCRIPTORS = set(
    "weak strong stronger secure insecure safe unsafe expired expiring wrong incorrect correct invalid " +
    "valid required optional empty blank missing short long simple complex complicated random unique " +
    "same different saved stored hashed encrypted leaked stolen compromised changed reset locked " +
    "blocked rejected accepted working broken forgotten lost new old current previous temporary " +
    "default generated manager policy rules requirements field box reset hint strength checker " +
    "protected enough ok okay fine good bad better worse too very really not"
  );

  /* ------------------------------------------------------------------ cues
   * The phrase that announces a value, what kind of value follows, and how
   * sure that makes us. Matched on normalised words, allowing a typo in the
   * longer ones and ignoring plural endings. */
  var CUES = [
    // secrets
    ["password", "SECRET", 1.0], ["passwd", "SECRET", 1.0], ["pwd", "SECRET", 0.95],
    ["pw", "SECRET", 0.85], ["pass", "SECRET", 0.6], ["passcode", "SECRET", 0.95],
    ["passphrase", "SECRET", 1.0], ["pass phrase", "SECRET", 1.0], ["pass word", "SECRET", 1.0],
    ["login password", "SECRET", 1.0], ["wifi password", "SECRET", 1.0], ["wi fi password", "SECRET", 1.0],
    ["master password", "SECRET", 1.0], ["app password", "SECRET", 1.0],
    ["security answer", "SECRET", 0.95], ["secret answer", "SECRET", 0.95],
    ["maiden name", "SECRET", 0.9], ["mother's maiden name", "SECRET", 0.95],
    ["first pet", "SECRET", 0.7], ["pet's name", "SECRET", 0.6],
    ["secret", "CREDENTIAL", 0.7], ["secret key", "CREDENTIAL", 1.0], ["api key", "CREDENTIAL", 1.0],
    ["apikey", "CREDENTIAL", 1.0], ["access key", "CREDENTIAL", 1.0], ["private key", "CREDENTIAL", 1.0],
    ["access token", "CREDENTIAL", 1.0], ["auth token", "CREDENTIAL", 1.0], ["token", "CREDENTIAL", 0.75],
    ["bearer", "CREDENTIAL", 0.8], ["session id", "CREDENTIAL", 0.85], ["cookie", "CREDENTIAL", 0.6],
    ["recovery code", "CREDENTIAL", 1.0], ["backup code", "CREDENTIAL", 1.0], ["seed phrase", "CREDENTIAL", 1.0],
    ["recovery phrase", "CREDENTIAL", 1.0], ["license key", "CREDENTIAL", 0.9], ["licence key", "CREDENTIAL", 0.9],
    // numeric secrets
    ["pin", "PIN", 0.85], ["mpin", "PIN", 1.0], ["atm pin", "PIN", 1.0], ["upi pin", "PIN", 1.0],
    ["pin code", "PIN", 0.5], ["pin number", "PIN", 0.9], ["door code", "PIN", 0.95],
    ["lock code", "PIN", 0.95], ["gate code", "PIN", 0.95], ["alarm code", "PIN", 0.95],
    ["locker code", "PIN", 0.95], ["safe code", "PIN", 0.9], ["unlock code", "PIN", 0.95],
    ["screen lock", "PIN", 0.8], ["passkey", "PIN", 0.9],
    ["otp", "OTP", 0.95], ["one time password", "OTP", 1.0], ["verification code", "OTP", 1.0],
    ["auth code", "OTP", 0.95], ["authentication code", "OTP", 1.0], ["security code", "CVV", 0.85],
    ["2fa code", "OTP", 1.0], ["login code", "OTP", 0.95], ["confirmation code", "OTP", 0.8],
    ["cvv", "CVV", 0.95], ["cvc", "CVV", 0.95], ["cvv2", "CVV", 0.95],
    // identifiers
    ["username", "USERNAME", 0.95], ["user name", "USERNAME", 0.95], ["user id", "USERNAME", 0.95],
    ["userid", "USERNAME", 0.95], ["login id", "USERNAME", 0.95], ["login", "USERNAME", 0.6],
    ["handle", "USERNAME", 0.5], ["gamertag", "USERNAME", 0.9], ["screen name", "USERNAME", 0.8],
    ["account number", "ACCOUNT", 1.0], ["account no", "ACCOUNT", 1.0], ["acct", "ACCOUNT", 0.9],
    ["a/c", "ACCOUNT", 0.9], ["ac no", "ACCOUNT", 0.9], ["bank account", "ACCOUNT", 1.0],
    ["account", "ACCOUNT", 0.55], ["iban", "ACCOUNT", 1.0], ["swift", "ACCOUNT", 0.8],
    ["routing number", "ACCOUNT", 1.0], ["sort code", "ACCOUNT", 1.0], ["ifsc", "ACCOUNT", 0.9],
    ["upi", "UPI", 0.9], ["upi id", "UPI", 1.0], ["vpa", "UPI", 0.9],
    ["customer id", "ID", 0.95], ["customer number", "ID", 0.95], ["cif", "ID", 0.9],
    ["employee id", "ID", 0.95], ["emp id", "ID", 0.95], ["employee number", "ID", 0.95],
    ["staff id", "ID", 0.95], ["member id", "ID", 0.9], ["membership number", "ID", 0.9],
    ["policy number", "ID", 0.95], ["policy no", "ID", 0.95], ["claim number", "ID", 0.9],
    ["roll number", "ID", 0.9], ["roll no", "ID", 0.9], ["registration number", "ID", 0.85],
    ["reg no", "ID", 0.85], ["enrollment number", "ID", 0.9], ["enrolment number", "ID", 0.9],
    ["application number", "ID", 0.85], ["reference number", "ID", 0.7], ["ref no", "ID", 0.7],
    ["ticket number", "ID", 0.6], ["pnr", "ID", 0.8], ["order id", "ID", 0.5],
    ["consumer number", "ID", 0.9], ["ca number", "ID", 0.85], ["meter number", "ID", 0.85],
    ["ration card", "ID", 0.95], ["voter id", "ID", 1.0], ["epic number", "ID", 1.0],
    ["driving licence", "ID", 1.0], ["driving license", "ID", 1.0], ["licence number", "ID", 1.0],
    ["license number", "ID", 1.0], ["dl number", "ID", 1.0], ["passport number", "ID", 1.0],
    ["passport", "ID", 0.8], ["pan number", "ID", 1.0], ["pan card", "ID", 1.0], ["pan", "ID", 0.6],
    ["aadhaar", "ID", 0.95], ["aadhar", "ID", 0.95], ["adhaar", "ID", 0.95], ["uid", "ID", 0.8],
    ["uan", "ID", 0.95], ["pf number", "ID", 0.9], ["esic", "ID", 0.9], ["abha", "ID", 0.9],
    ["ssn", "ID", 1.0], ["social security", "ID", 1.0], ["national id", "ID", 1.0],
    ["tax id", "ID", 0.95], ["gstin", "ID", 0.9], ["tin", "ID", 0.6], ["vehicle number", "ID", 0.8],
    ["registration plate", "ID", 0.8], ["chassis number", "ID", 0.9], ["imei", "ID", 1.0],
    ["serial number", "ID", 0.6], ["device id", "ID", 0.8], ["ip address", "ID", 0.8],
    ["mac address", "ID", 0.8], ["card number", "ID", 1.0], ["credit card", "ID", 0.9],
    ["debit card", "ID", 0.9]
  ];

  /* Words that may sit between a cue and its value: "my password IS NOW x",
     "change it FROM x TO y". */
  var LINKERS = set(
    "is are was were be been being am :- := : = => -> \u2192 - \u2013 \u2014 to as of it it's its now then " +
    "currently still just simply literally exactly set changed change changing update updated reset " +
    "from into will would should shall can could new old current my the a an our your his her their " +
    "called named reads says remains stays became becomes equals equal being this that which " +
    "mine yours ours default original temporary actual real correct right"
  );

  /* Between two values given together: "from adi123 TO aditya". */
  var JOINERS = set("to and or then , / | -> \u2192 => from into also plus &");

  /* Phrases that describe how a secret is built instead of giving it. */
  var HINT_WORDS = set(
    "same similar based derived combination made consists consisting composed built starts start " +
    "starting begins beginning ends ending contains containing backwards reversed spelled spelt " +
    "initials birthday birth born dob anniversary dog cat pet pets mother mom mum father dad wife " +
    "husband son daughter kid kids child children brother sister girlfriend boyfriend favourite " +
    "favorite team car city hometown school college lucky phone mobile number vehicle nickname " +
    "surname lastname firstname"
  );

  /* ------------------------------------------------------------ personal cues */

  var RELATIONS = set(
    "wife husband spouse partner son daughter child kid mother mom mum mummy amma maa father dad daddy " +
    "papa appa baba brother bro sister sis sibling uncle aunt aunty auntie cousin nephew niece grandson " +
    "granddaughter grandfather grandpa grandmother grandma nani nana dadi dada fiance fiancee girlfriend " +
    "boyfriend friend bestie roommate flatmate neighbour neighbor colleague coworker boss manager " +
    "supervisor employee assistant landlord landlady tenant maid driver cook doctor dentist therapist " +
    "lawyer advocate accountant teacher tutor professor student classmate client patient bhai didi bhaiya " +
    "chacha chachi mama mami mausi bua jiju bhabhi sister-in-law brother-in-law father-in-law " +
    "mother-in-law son-in-law daughter-in-law ex"
  );

  /* Name parts shared by millions. Hidden as part of a full name, but not
     remembered on their own, or every later "Singh" would be masked. */
  var COMMON_NAME_PARTS = set(
    "singh kaur kumar kumari devi lal prasad sharma verma gupta patel shah khan reddy rao das nair " +
    "iyer iyengar pillai menon naidu yadav jain mehta joshi mishra pandey tiwari chauhan thakur ali " +
    "ahmed ahmad begum bai ben bhai mohammed mohammad muhammad md sri shri babu raj ram"
  );

  var HONORIFICS = set("mr mrs ms miss mx dr prof shri sri smt kumari kum sh late capt col maj");

  /* Before a name, these make it about someone in the user's life. */
  var NAME_INTROS = [
    "my name is", "my name's", "name is", "i am", "i'm", "im", "this is", "call me", "it's", "its",
    "signed", "regards", "thanks", "thank you", "cheers", "sincerely", "yours truly", "best",
    "warm regards", "kind regards", "i'm called", "they call me", "named", "called",
    "my full name is", "full name", "my surname is", "surname", "my last name is", "my first name is"
  ];

  /* Before a name, these usually mean a public figure, not a private one. */
  var PUBLIC_CONTEXT = set(
    "about who whom biography life history quotes quote books book novel novels poems written wrote " +
    "directed starring president prime minister pm cm chief minister governor king queen emperor " +
    "actor actress singer cricketer player captain author poet scientist philosopher leader ceo " +
    "founder chairman politician mahatma saint guru sir lord film movie album famous"
  );

  /* ------------------------------------------------------------- addresses */

  /* Words that on their own point at an address. */
  var ADDRESS_STRONG = set(
    "house flat apartment apt apts h.no hno h.n. plot bungalow villa building bldg society residency " +
    "enclave apartments chs niwas nivas bhavan bhawan sadan nilayam nilaya kutir street st road rd " +
    "marg lane ln gali cross avenue ave highway hwy bypass nagar colony layout sector phase extension " +
    "extn puram pet palya halli wadi pada peth bagh ganj gunj abad vihar kunj bazaar bazar basti " +
    "mohalla near opp opposite behind po p.o. dist district distt tal taluka tehsil mandal village " +
    "vill pincode zip zipcode postcode post s/o d/o w/o c/o at/po at/post"
  );

  var ADDRESS_WORDS = set(
    "house flat apartment apt apts h.no hno h.n. door plot bungalow villa floor ground first second " +
    "building bldg block tower wing complex society residency residence enclave heights apartments " +
    "towers chs niwas nivas bhavan bhawan sadan nilayam nilaya kutir mansion manor " +
    "street st road rd marg lane ln gali cross main avenue ave highway hwy bypass circle chowk " +
    "nagar colony layout sector sec phase extension extn stage puram pet palya halli wadi pada peth " +
    "bagh ganj gunj abad vihar kunj enclave market bazaar bazar basti mohalla ward " +
    "near opp opposite behind beside next landmark junction station depot " +
    "po p.o. post dist district distt tal taluka tehsil mandal village vill gram block " +
    "pin pincode zip zipcode postcode city town state"
  );

  var ADDRESS_CUES = [
    "my address is", "address is", "address:", "my address", "home address", "office address",
    "current address", "permanent address", "residential address", "i live at", "i live in",
    "i stay at", "i stay in", "i'm staying at", "we live at", "we live in", "we stay at",
    "residing at", "resident of", "r/o", "deliver to", "ship to", "send it to", "courier to",
    "come to", "my house is", "my home is", "my flat is", "located at", "reside at",
    "bill to", "billing address", "shipping address", "delivery address"
  ];

  /* ----------------------------------------------------------- other context */

  var WORK_CUES = [
    "i work at", "i work for", "i work in", "work at", "working at", "working for", "i'm working at",
    "employed at", "employed by", "my company", "my employer", "my office", "my firm", "our company",
    "i joined", "joined", "my client", "i study at", "studying at", "my school", "my college",
    "my university", "i intern at", "interning at", "my bank", "i bank with", "banking with"
  ];

  var FROM_CUES = [
    "i'm from", "i am from", "im from", "i live in", "i stay in", "we live in", "my hometown",
    "my home town", "my native", "native place", "born in", "grew up in", "moved to", "relocated to",
    "near my house", "near my home", "my area", "my locality", "my neighbourhood", "my neighborhood"
  ];

  var BIRTH_CUES = ["born on", "birthday", "birth date", "date of birth", "dob", "d.o.b", "bday", "born"];

  var SPLIT_WORDS = set(
    "part half first last rest remaining remainder begins starts ends prefix suffix letters " +
    "characters chars digits middle piece portion bit"
  );

  /* ------------------------------------------------------------ key: value */

  var SENSITIVE_KEYS = [
    [/pass(word|wd|code|phrase)?$|^pwd$|^pw$|secret|token|api.?key|private.?key|access.?key|auth|credential|cookie|session/, "SECRET"],
    [/^(user(name|.?id)?|login(.?id)?|uid|handle)$/, "USERNAME"],
    [/e.?mail|mail.?id/, "EMAIL"],
    [/phone|mobile|contact.?(no|number)|cell|tel(ephone)?$|whatsapp/, "PHONE"],
    [/address|^addr$|street|locality|landmark|house|flat|^city$|^pin.?code$|^pincode$|^zip/, "ADDRESS"],
    [/^(full.?)?name$|first.?name|last.?name|surname|middle.?name|father|mother|spouse|guardian|husband|wife|nominee/, "NAME"],
    [/d\.?o\.?b|birth|birthday/, "DOB"],
    [/^age$/, "AGE"],
    [/account|acct|a\/c|iban|swift|ifsc|routing|sort.?code|upi|vpa/, "ACCOUNT"],
    [/aadhaa?r|aadhar|adhaar|^pan$|pan.?(no|number|card)|passport|licen[cs]e|voter|ssn|social.?security|gstin|^tin$|^uan$|employee.?id|emp.?id|customer.?id|policy|member.?id|roll.?no|reg(istration)?.?no|^id$|id.?number/, "ID"],
    [/card.?(no|number)|^card$|cvv|cvc|expiry|exp.?date/, "CARD"],
    [/^otp$|^pin$|mpin/, "PIN"],
    [/salary|ctc|income|compensation|^pay$|bonus|net.?worth|balance/, "FINANCIAL"],
    [/diagnos|disease|condition|medication|medicine|allerg|blood.?group|illness|symptom/, "HEALTH"],
    [/religion|caste|community|ethnicity/, "NRP"],
    [/^ip(.?address)?$|^mac(.?address)?$|imei|device.?id|serial/, "ID"],
    [/lat(itude)?$|lon(g|gitude)?$|^lng$|coordinates|gps|location/, "COORD"]
  ];

  /* ----------------------------------------------------------- sensitive topics
   * These cannot be masked without destroying the question ("is this diabetes
   * medication safe?"), so they produce a warning instead, unless a rule says
   * to hide them. */
  var TOPICS = {
    HEALTH: set(
      "diagnosed diagnosis disease disorder syndrome hiv aids cancer tumour tumor chemotherapy chemo " +
      "diabetes diabetic hypertension depression depressed anxiety bipolar schizophrenia adhd autism " +
      "autistic ptsd ocd dementia alzheimer's alzheimers parkinson's epilepsy seizure seizures asthma " +
      "tuberculosis tb hepatitis std stds sti herpes syphilis pregnant pregnancy miscarriage abortion " +
      "infertility ivf therapy therapist psychiatrist psychologist counselling counseling rehab " +
      "addiction addicted overdose suicidal suicide self-harm antidepressant antidepressants insulin " +
      "prescription medication medications surgery disability disabled thyroid pcos pcod covid " +
      "positive negative biopsy mri scan dialysis transplant"
    ),
    BELIEF: set(
      "hindu muslim christian sikh jain buddhist parsi jewish atheist religion religious caste dalit " +
      "brahmin kshatriya vaishya shudra obc sc/st scheduled tribe tribal"
    ),
    SEXUALITY: set("gay lesbian bisexual bi transgender trans queer lgbt lgbtq homosexual asexual pansexual"),
    LEGAL: set("arrested arrest fir chargesheet convicted conviction jail prison bail lawsuit sued court custody"),
    MONEY: set("salary ctc lpa income debt debts loan loans emi cibil overdraft bankrupt bankruptcy networth")
  };

  var TOPIC_LABEL = {
    HEALTH: "health", BELIEF: "religion or caste", SEXUALITY: "sexual orientation or gender identity",
    LEGAL: "legal matters", MONEY: "personal finances"
  };

  /* Letters that look Latin but are not, used to disguise a keyword. */
  var CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
    "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u04bb": "h", "\u0501": "d",
    "\u03bf": "o", "\u03b1": "a", "\u03c1": "p", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k",
    "\u03bd": "v", "\u03c4": "t", "\u03c5": "u", "\u0410": "a", "\u0415": "e", "\u041e": "o",
    "\u0420": "p", "\u0421": "c", "\u0425": "x", "\u0412": "b", "\u041d": "h", "\u041a": "k",
    "\u041c": "m", "\u0422": "t"
  };

  var NUMBER_WORDS = {
    zero: "0", oh: "0", nil: "0", one: "1", two: "2", three: "3", four: "4", five: "5",
    six: "6", seven: "7", eight: "8", nine: "9", shunya: "0"
  };
  var MULTIPLIERS = { double: 2, triple: 3, treble: 3 };

  return {
    COMMON: COMMON, COMMON_PASSWORDS: COMMON_PASSWORDS, DESCRIPTORS: DESCRIPTORS, CUES: CUES, LINKERS: LINKERS, JOINERS: JOINERS,
    HINT_WORDS: HINT_WORDS, RELATIONS: RELATIONS, HONORIFICS: HONORIFICS, COMMON_NAME_PARTS: COMMON_NAME_PARTS, NAME_INTROS: NAME_INTROS,
    PUBLIC_CONTEXT: PUBLIC_CONTEXT, ADDRESS_WORDS: ADDRESS_WORDS, ADDRESS_STRONG: ADDRESS_STRONG, ADDRESS_CUES: ADDRESS_CUES,
    WORK_CUES: WORK_CUES, FROM_CUES: FROM_CUES, BIRTH_CUES: BIRTH_CUES, SPLIT_WORDS: SPLIT_WORDS,
    SENSITIVE_KEYS: SENSITIVE_KEYS, TOPICS: TOPICS, TOPIC_LABEL: TOPIC_LABEL,
    CONFUSABLES: CONFUSABLES, NUMBER_WORDS: NUMBER_WORDS, MULTIPLIERS: MULTIPLIERS
  };
})();

if (typeof module !== "undefined" && module.exports) module.exports = OpaqueLexicon;
