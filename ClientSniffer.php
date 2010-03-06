<?php

class ClientSniffer {

	/* TODO
	 *
	 * Add the following methods: `addDeduction`, `addSynonym`, `addRule`
	 * Mechanism for adding new strings to the queues
	 *
	 */

	private /* String */ $user_agent;
	private /* Array  */ $db;

	/* Constants */

	/* NOTE: Constants are reserved for supported clients.
	 * You can extend the default constants by calling the
	 * `addConstant` method.
	 */

	const UNKNOWN_NAME = "Unknown";
	const UNKNOWN_VER = -1;

	const OPERA = "Opera";
	const FIREFOX = "Firefox";
	const IE = "Internet Explorer";
	const CHROME = "Chrome";
	const SAFARI = "Safari";
	const KONQUEROR = "Konqueror";
	const ICAB = "iCab";

	const WINDOWS = "Windows";
	const LINUX = "Linux";
	const MACOS = "Mac OS";

	const WEBKIT = "WebKit";
	const GECKO = "Gecko";
	const TRIDENT = "Trident";
	const TASMAN = "Tasman";
	const KHTML = "KHTML";
	const PRESTO = "Presto";

	/* Synonyms */

	/* NOTE: The following synonyms are not intended for public use,
	 * so you won't find constants associated with them.
	 * You can extend the default synonyms by calling the
	 * `addSynonym` method.
	 */

	private static /* Array */ $synonyms = array(
		"Iron"			=> self::CHROME,
		"Iceweasel"		=> self::FIREFOX,
		"Minefield"		=> self::FIREFOX,
		"Shiretoko"		=> self::FIREFOX,
		"Namoroka"		=> self::FIREFOX,
		"BonEcho"		=> self::FIREFOX,
		"GranParadiso"	=> self::FIREFOX,
		"MSIE"			=> self::IE,

		"Win"			=> self::WINDOWS,
		"Windows NT"	=> self::WINDOWS,
		"Mac"			=> self::MACOS,
		"Macintosh"		=> self::MACOS,
		"PowerPC"		=> self::MACOS,
		"PPC"			=> self::MACOS,
		"FreeBSD"		=> self::LINUX,
		"SunOS"			=> self::LINUX,
	);

	/* Priority Queues */

	/* NOTE: Do NOT change the order of these queues,
	 * as it may break the whole detection system!
	 */

	private static /* Array */ $browser_queue = array(
		self::OPERA, self::FIREFOX, self::IE, self::CHROME, self::SAFARI, self::KONQUEROR, self::ICAB,
		"Iron", "Iceweasel", "Minefield", "Shiretoko", "Namoroka", "BonEcho", "GranParadiso", "MSIE"
	);

	private static /* Array */ $os_queue = array(
		"Windows NT",
		self::WINDOWS, self::LINUX, self::MACOS,
		"Win", "Mac", "Macintosh", "PowerPC", "PPC", "FreeBSD", "SunOS"
	);

	private static /* Array */ $engine_queue = array(
		self::WEBKIT, self::GECKO, self::TRIDENT, self::TASMAN, self::KHTML, self::ICAB, self::PRESTO,
	);

	/* Deductions */

	/* NOTE: You can extend the default deductions by calling the
	 * `addDeduction` method.
	 */

	private static /* Array */ $deductions = array(
		array(
			array(
				"browser_name"	=> self::IE,
				"os_name"		=> self::MACOS
			),
			array("engine_name"	=> self::TASMAN)
		),

		array(
			array(
				"browser_name"	=> self::IE,
				"os_name"		=> self::WINDOWS,
			),
			array("engine_name"	=> self::TRIDENT)
		),

		array(
			array(
				"browser_name"	=> self::SAFARI,
				"os_name"		=> self::LINUX
			),
			array("engine_name"	=> self::UNKNOWN_NAME)
		),

		array(
			array(
				"os_name"		=> self::WINDOWS,
				"os_ver"		=> "5.0"
			),
			array("os_ver"	=> "2000")
		),

		array(
			array(
				"os_name"		=> self::WINDOWS,
				"os_ver"		=> array("5.1", "5.2")
			),
			array("os_ver"	=> "XP")
		),

		array(
			array(
				"os_name"		=> self::WINDOWS,
				"os_ver"		=> "6.0"
			),
			array("os_ver"	=> "Vista")
		),

		array(
			array(
				"os_name"		=> self::WINDOWS,
				"os_ver"		=> "6.1"
			),
			array("os_ver"	=> "7")
		),
	);

	/* Rules */

	/* NOTE: You can extend the default assumptions by calling the
	 * `addRule` method.
	 */

	private static /* Array */ $rules = array(
		"os_name" => array(
			self::WINDOWS		=> array(NULL, '/(?:NT )?((?:[0-9]+[\.]?)*)/i', false),
			self::MACOS			=> array(NULL, '/(?:Platform|X )?((?:[0-9]+[\._]?)*)/i', false),
		),

		"browser_name" => array(
			self::OPERA			=> array("Version", NULL, true),
			self::SAFARI		=> array("Version", NULL, false),
		),

		"engine_name" => array(
			self::GECKO			=> array("rv:", NULL, false),
		),
	);

	/* Static String utilities */

	public static function /* boolean */ parse($ua_string) {
		if (!$ua_string || $ua_string == "")
			return false;

		$match = self::regexp('/([a-z0-9]+\/?[0-9\.]* ?)+(\((?:[a-z0-9_\.\:\-\/ ]*(?:; )?)*\) ?)*(.*)/i', $ua_string);

		return $match;
	}

	private static function /* Array */ regexp($regexp, $string) {
		preg_match($regexp, $string, $result);

		if (count($result) > 1 && trim(implode(array_slice($result, 1), "")) != "")
			return array_slice($result, 1);

		return NULL;
	}

	/* Static Synonyms utilities */

	private static function /* String */ getSynonym($string) {
		if (isset(self::$synonyms[$string]))
			return self::$synonyms[$string];

		return NULL;
	}

	private static function /* boolean */ hasSynonym($string) {
		return(self::getSynonym($string) != NULL);
	}

	private static function /* boolean */ is($string, $family) {
		if (self::hasSynonym($string))
			return (self::getSynonym($string) == $family);

		return ($string == $family);
	}

	/* Instance String utilities */

	private function /* int */ search($word, $string = NULL) {
		$string = ($string) ? $string : $this->user_agent;
		$search = strpos($string, $word);
		return (($search !== false) ? $search + strlen($word) : -1);
	}

	private function /* String */ cut($index) {
		return (substr($this->user_agent, $index));
	}

	private function /* boolean */ contains($word, $string = NULL) {
		return ($this->search($word, $string) != -1);
	}

	/* Istance */

	public function /* Constructor */ __construct($ua_string = NULL) {
		if ($ua_string && !self::parse($ua_string)) die("La stringa non e' corretta");

		$this->user_agent = (($ua_string) ? $ua_string : $_SERVER['HTTP_USER_AGENT']);

		$this->db = array(
			"os_name"			=> self::UNKNOWN_NAME,
			"os_ver"			=> self::UNKNOWN_VER,

			"browser_name"		=> self::UNKNOWN_NAME,
			"browser_ver"		=> self::UNKNOWN_VER,

			"engine_name"		=> self::UNKNOWN_NAME,
			"engine_ver"		=> self::UNKNOWN_VER,
		);

		$this->detectOS();
		$this->detectBrowser();
		$this->detectEngine();

		$this->deduct();
	}

	/* Database utilities */

	private function /* void */ set($name, $value) {
		$this->db[$name] = $value;
	}

	public function /* String */ get($name) {
		if (isset($this->db[$name]))
			return $this->db[$name];

		return NULL;
	}

	public function /* boolean */ has($name) {
		return ($this->get($name) != NULL && 
			!($this->get($name) == self::UNKNOWN_NAME) || ($this->get($name) == self::UNKNOWN_VER));
	}

	public function /* String */ getUserAgent() {
		return $this->user_agent;
	}

	/* Detection utilities */

	private function /* void */ detect($name, $queue) {
		for ($i = 0; $i < count($queue) && !$this->has($name); ++$i)
			if ($this->contains($queue[$i]))
				$this->set($name, $queue[$i]);
	}

	private function /* Array */ rules($context) {
		$rules = self::$rules[$context];

		if (!$rules) return NULL;

		$search = $this->get($context);
		$regexp = '/\/?([0-9\.]*)/i';
		$iterative = false;

		foreach($rules as $name => $values) {
			if (self::is($this->get($context), $name)) {
				if ($values[0]) $search = $values[0];
				if ($values[1]) $regexp = $values[1];
				if ($values[2]) $iterative = $values[2];
			}
		}

		$index = $this->search($search);

		if ($index == -1 && $search != $this->get($context) && $iterative)
			$index = $this->search($this->get($context));

		if ($index == -1) return NULL;

		$string = trim($this->cut($index));
		$match = self::regexp($regexp, $string);

		return $match;
	}

	private function /* void */ detectOS() {
		$this->detect("os_name", self::$os_queue);

		if ($this->has("os_name")) {
			$match = $this->rules("os_name");
			if ($match) $this->set("os_ver", str_replace("_", ".", $match[0]));
		}

		if (self::hasSynonym($this->get("os_name")))
			$this->set("os_name", self::getSynonym($this->get("os_name")));
	}

	private function /* void */ detectBrowser() {
		$this->detect("browser_name", self::$browser_queue);

		if ($this->has("browser_name")) {
			$match = $this->rules("browser_name");
			if ($match) $this->set("browser_ver", str_replace("_", ".", $match[0]));
		}

		if (self::hasSynonym($this->get("browser_name")))
			$this->set("browser_name", self::getSynonym($this->get("browser_name")));
	}

	private function /* void */ detectEngine() {
		$this->detect("engine_name", self::$engine_queue);

		if ($this->has("engine_name")) {
			$match = $this->rules("engine_name");
			if ($match) $this->set("engine_ver", str_replace("_", ".", $match[0]));
		}
	}

	private function /* void */ deduct() {
		foreach(self::$deductions as $rule) {
			if (is_array($rule) && count($rule) == 2) {
				$test = true;

				foreach($rule[0] as $name => $values) {
					$accum = false;

					if (is_array($values))
						foreach($values as $v) $accum = $accum || ($this->get($name) == $v);
					else
						$accum = ($this->get($name) == $values);

					$test = $test && $accum;
				}

				if ($test)
					foreach($rule[1] as $name => $value)
						$this->set($name, $value);
			}
		}
	}

	public function /* String */ sniff() {
		$output = "<p><code>".$this->getUserAgent()."</code></p>\n";
		$output .= "<dl>\n";
		$output .= "<dt>OS</dt><dd>".$this->get("os_name") ." ". $this->get("os_ver")."</dd>\n";
		$output .= "<dt>Browser</dt><dd>".$this->get("browser_name") ." ". $this->get("browser_ver")."</dd>\n";
		$output .= "<dt>Engine</dt><dd>".$this->get("engine_name") ." ". $this->get("engine_ver")."</dd>\n";
		$output .= "</dl>\n";

		return $output;
	}

	public static function test($tests) {
		foreach($tests as $test) {
			$sniffer = new self($test);
			echo $sniffer->sniff();
		}
	}

}

$sniffer = new ClientSniffer();
echo $sniffer->sniff();

ClientSniffer::test(array(
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
