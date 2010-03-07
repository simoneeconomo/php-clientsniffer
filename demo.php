<?php

require_once("ClientSniffer.php");

/* OS */

ClientSniffer::teach(
	"os_name", "Windows", NULL, array("Windows NT", '/(?:NT )?((?:[0-9]+[\.]?)*)/i', true)
);

ClientSniffer::teach(
	"os_name", "Linux", array("FreeBSD", "SunOS"), NULL
);

ClientSniffer::teach(
	"os_name", "Mac OS", array("Mac", "Macintosh", "PowerPC", "PPC"), array(NULL, '/(?:Platform|X )?((?:[0-9]+[\._]?)*)/i', false)
);

/* Browser */

ClientSniffer::teach(
	"browser_name", "Opera", NULL, array("Version", NULL, true)
);

ClientSniffer::teach(
	"browser_name", "Firefox", array("Iceweasel", "Minefield", "Shiretoko", "Namoroka", "BonEcho", "GranParadiso"), NULL
);

ClientSniffer::teach(
	"browser_name", "Internet Explorer", array("MSIE"), NULL
);

ClientSniffer::teach(
	"browser_name", "Chrome", array("Iron"), NULL
);

ClientSniffer::teach(
	"browser_name", "Safari", NULL, array("Version", NULL, false)
);

ClientSniffer::teach(
	"browser_name", "Konqueror", NULL, NULL
);

ClientSniffer::teach(
	"browser_name", "iCab", NULL, NULL
);

ClientSniffer::teach(
	"browser_name", "OmniWeb", NULL, NULL
);

/* Engine */

ClientSniffer::teach(
	"engine_name", "WebKit", NULL, NULL
);

ClientSniffer::teach(
	"engine_name", "Gecko", NULL, array("rv:", NULL, false)
);

ClientSniffer::teach(
	"engine_name", "Trident", NULL, NULL
);

ClientSniffer::teach(
	"engine_name", "Tasman", NULL, NULL
);

ClientSniffer::teach(
	"engine_name", "KHTML", NULL, NULL
);

ClientSniffer::teach(
	"engine_name", "iCab", NULL, NULL
);

ClientSniffer::teach(
	"engine_name", "Presto", NULL, NULL
);


/* AfterRules */


ClientSniffer::guess(
	array(
		"browser_name"	=> "Internet Explorer",
		"os_name"		=> "Mac OS"
	),
	array("engine_name"	=> "Tasman")
);

ClientSniffer::guess(
	array(
		"browser_name"	=> "Internet Explorer",
		"os_name"		=> "Windows",
	),
	array("engine_name"	=> "Trident")
);


ClientSniffer::guess(
	array(
		"browser_name"	=> "Safari",
		"os_name"		=> "Linux"
	),
	array("engine_name"	=> ClientSniffer::UNKNOWN_NAME)
);

ClientSniffer::guess(
	array(
		"os_name"		=> "Windows",
		"os_ver"		=> array("5", "5.0")
	),
	array("os_ver"		=> "2000")
);

ClientSniffer::guess(
	array(
		"os_name"		=> "Windows",
		"os_ver"		=> array("5.1", "5.2")
	),
	array("os_ver"		=> "XP")
);

ClientSniffer::guess(
	array(
		"os_name"		=> "Windows",
		"os_ver"		=> "6.0"
	),
	array("os_ver"		=> "Vista")
);

ClientSniffer::guess(
	array(
		"os_name"		=> "Windows",
		"os_ver"		=> array("6.1", "6.2")
	),
	array("os_ver"		=> "7")
);

ClientSniffer::guess(
	array(
		"browser_name"		=> "OmniWeb",
	),
	array("engine_name"	=> "WebKit")
);

ClientSniffer::test(array(
	"", // $_SERVER['HTTP_USER_AGENT'])
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; Maxthon; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; InfoPath.1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
	"Mozilla/4.0 (compatible; MSIE 5.0; Mac OS X)",
	"Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_4_11; hu-hu) AppleWebKit/531.21.8 (KHTML, like Gecko) Version/4.0.4 Safari/531.21.10",
	"Opera/9.80 (X11; Linux x86_64; U; it) Presto/2.2.15 Version/10.10",
	"Links (2.2; Linux 2.6.32-ARCH x86_64; 80x24)",
	"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2) Gecko/20100131 Namoroka/3.6",
	"Midori/0.2.2 (X11; Linux x86_64; U; it-it) WebKit/531.2+",
	"Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.0)",
	"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6 Camino/1.5.1",
	"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6 Camino/1.5.1",
	"Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_4_11; hu-hu) AppleWebKit/531.21.8 (KHTML, like Gecko) Version/4.0.4 Safari/531.21.10",
	"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.0.1) Gecko/20060203 Camino/1.0rc1",
	"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/418.9 (KHTML, like Gecko) Shiira/1.2.2 Safari/125",
	"Mozilla/4.0 (compatible; MSIE 5.0; Mac OS X)",
	"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_7; en-US) AppleWebKit/530.18+(KHTML, like Gecko, Safari/528.16)",
	"Mozilla/4.5 (compatible; OmniWeb/4.1.1-v424.6; Mac_PowerPC)",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; Maxthon; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; InfoPath.1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
	"Mozilla/4.0 (Windows; MSIE 6.0; Windows NT 5.0)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; chromeframe; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; MAXTHON 2.0)",
	"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.2; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)",
	"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 5.2; WOW64; .NET CLR 2.0.50727)",
	"Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",
	"Mozilla/4.0 (compatible; MSIE 5.5; Windows NT5)",
	"Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; Q312461)",
	"Mozilla/4.0 (compatible; MSIE 4.01; Windows 95)",
	"Mozilla/2.0 (compatible; MSIE 3.0; Windows 3.1)",
	"Opera/9.62 (Windows NT 6.0; U; en) Presto/2.1.1",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; MyIE2; .NET CLR 1.1.4322)"
));

?>
