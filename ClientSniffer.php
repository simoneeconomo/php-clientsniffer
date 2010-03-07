<?php

class ClientSniffer {

	/* TODO
	 *
	 * Better synonyms handling
	 * `teach` method should accept bulk insertion
	 *
	 */

	private /* String */ $user_agent;
	private /* Array  */ $db;

	const UNKNOWN_NAME = "Unknown";
	const UNKNOWN_VER = -1;

	private static /* Array */ $priorities = array();
	private static /* Array */ $rules = array();
	private static /* Array */ $guesses = array();

	/* Extension utilities */

#	private static function /* void */ priority($context, $name, $lighter) {
#		$index = array_search(self::$known, $lighter);

#		if ($index) self::place(self::$known, $index, $name);
#	}

	public static function /* void */ guess($if, $then) {
		if (!is_array($if) || !is_array($then) || count($if) == 0 || count($then) == 0) return NULL;

		self::$guesses[] = array($if, $then);
	}

	public static function /* void */ teach($context, $name, $synonyms = NULL, $rules = NULL) {
		if (!$context || !$name) return NULL;

		if (!isset(self::$priorities[$context])) self::$priorities[$context] = array();
		if (!in_array($name, self::$priorities[$context])) self::$priorities[$context][] = $name;

		if ($synonyms && is_array($synonyms) && count($synonyms) > 0) {
			foreach($synonyms as $synonym)
				self::$priorities[$context][] = $synonym;

			$if = array($context => $synonyms);
			$then = array($context => $name);

			self::guess($if, $then);
		}

		if ($rules && is_array($rules) && count($rules) == 3) {
			if (!isset(self::$rules[$context])) self::$rules[$context] = array();

			self::$rules[$context][$name] = $rules;
		}
	}

	/* Static utilities */

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

#	private static function /* Array */ place($array, $index, $value) {
#		return array_splice($array, $index, count($array), array_merge(array($value), array_slice($array, $index))); 
#	}

	/* String utilities */

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

		$this->detect("os_name", "os_ver");
		$this->detect("browser_name", "browser_ver");
		$this->detect("engine_name", "engine_ver");

		$this->parseGuesses();
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

	private function /* void */ detect($name, $ver = NULL) {
		for ($i = 0; $i < count(self::$priorities[$name]) && !$this->has($name); ++$i)
			if ($this->contains(self::$priorities[$name][$i]))
				$this->set($name, self::$priorities[$name][$i]);

		if ($ver) {
			if ($this->has($name)) {
				$match = $this->parseRules($name);
				if ($match) $this->set($ver, str_replace("_", ".", $match[0]));
			}
		}
	}

	private function /* Array */ parseRules($context) {
		$rules = self::$rules[$context];

		if (!$rules) return NULL;

		$search = $this->get($context);
		$regexp = '/\/?([0-9\.]*)/i';
		$iterative = false;

		foreach($rules as $name => $values) {
			if ($this->get($context) == $name) {
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

	private function /* void */ parseGuesses() {
		foreach(self::$guesses as $rule) {
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

?>
