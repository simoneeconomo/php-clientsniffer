<?php

require_once("ClientSniffer.php");

ClientSniffer::systems(array(
	"Windows"			=> array("Windows NT", "Windows"),
	"Mac OS"			=> array("Mac OS X", "Mac", "Macintosh", "PowerPC", "PPC"),
	"Linux"				=> array("Linux", "FreeBSD", "OpenBSD", "SunOS")
));

ClientSniffer::browsers(array(
	"Links"				=> NULL,
	"Midori"			=> NULL,

	"Opera" => array(
		NULL,
		array("Version", "Opera")
	),

	"Camino"			=> NULL,

	"Firefox" 			=> array("Firefox", "Iceweasel", "Minefield", "Shiretoko", "Namoroka", "BonEcho", "GranParadiso"),
	"Internet Explorer"	=> array("MSIE"),
	"Chrome"			=> array("Chrome", "ChromePlus", "Iron"),

	"Shiira"			=> NULL,

	"Safari" => array(
		NULL,
		array("Version")
	),

	"Konqueror"			=> NULL,
	"iCab"				=> NULL,

	"OmniWeb"			=> NULL,
));

ClientSniffer::engines(array(
	"WebKit"			=> NULL,

	"Gecko" => array(
		NULL, 
		array("rv:")
	),

	"Trident"			=> NULL,
	"Tasman"			=> NULL,
	"KHTML"				=> NULL,
	"iCab"				=> NULL,
	"Presto"			=> NULL,
));


ClientSniffer::assume(
	array(
		"browser_name"	=> "Internet Explorer",
		"system_name"		=> "Mac OS"
	),
	array("engine_name"	=> "Tasman")
);

ClientSniffer::assume(
	array(
		"browser_name"	=> "Internet Explorer",
		"system_name"		=> "Windows",
	),
	array("engine_name"	=> "Trident")
);


ClientSniffer::assume(
	array(
		"browser_name"	=> "Safari",
		"system_name"		=> "Linux"
	),
	array("engine_name"	=> ClientSniffer::UNKNOWN_NAME)
);

ClientSniffer::assume(
	array(
		"system_name"		=> "Windows",
		"system_ver"		=> array("5", "5.0")
	),
	array("system_ver"		=> "2000")
);

ClientSniffer::assume(
	array(
		"system_name"		=> "Windows",
		"system_ver"		=> array("5.1", "5.2")
	),
	array("system_ver"		=> "XP")
);

ClientSniffer::assume(
	array(
		"system_name"		=> "Windows",
		"system_ver"		=> "6.0"
	),
	array("system_ver"		=> "Vista")
);

ClientSniffer::assume(
	array(
		"system_name"		=> "Windows",
		"system_ver"		=> array("6.1", "6.2")
	),
	array("system_ver"		=> "7")
);

ClientSniffer::assume(
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
