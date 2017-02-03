
<?php

/**
Given a http log file analyze log entries and prepares output ready for reporting
Usage: To be used via PHP command line (no arguments)
Input: Http access log file (to be passed as shown at the end of script)
**/
class LogAnalyzer {

    protected static $analysis = [];
    
    protected static $patterns = [
        "file" => "/\"GET\s(.*?)\sHTTP/",
        "referer" => "/\"http:\/\/(.*?)\"/",
        "status" => "/\s\d{3}\s/",
        "user_agent" => "/(\"([a-zA-Z]*)\/(\d\.\d))(.*?)\)\"/"
    ];

    /**
    Analyzes and aggregates matches for page, referers, http - status, user agents and possible malicious attacks
    @param string - log entry
    @return void
    **/
    protected static function analyzeMatches(string $lineBuffer) {
        
        foreach (self::$patterns as $type=>$pattern) {
            $matches = [];
            $match = "";
            
            preg_match_all($pattern, $lineBuffer, $matches);  
            if (in_array($type, ['file', 'referer'])) {
                if (count($matches) >= 2 && isset($matches[1][0])) { 
                    $match =  trim($matches[1][0]);
                }                 
            } else if (in_array($type, ['status', 'user_agent'])) {
                if (count($matches) >= 1 && isset($matches[0][0])) { 
                    $match =  trim($matches[0][0]);
                }
            }
            if ($match != "") {
               self::addToReport($type, $match); 
            }                                    
        }
    } 
    
    /**
    Adds an entry to report data
    @param type - e.g Request URI, Referer, User Agent
    @param match - pattern matched in log entry
    **/
    protected static function addToReport(string $type, string $match) {
         $count = 1;
         // make a new set for type key
         if (!array_key_exists($type, self::$analysis)) {
            self::$analysis[$type] = [];
         }  else {
            if (isset(self::$analysis[$type][$match])) {
                $count = self::$analysis[$type][$match];
                $count++; 
            }
         }
         // add data to set
         self::$analysis[$type][$match] = $count; 
    }
    
    /**
    Checks for malicous attack patterm in log entries
    **/
    protected static function checkMaliciousAttack() {
         
         $pattern = "";
         
         $pattern = "/(eval\()|(UNION+SELECT)|(base64_)|(\/localhost)|(etc\/passwd)|(\/pingserver)|(\.bash)/i";
         foreach (self::$analysis['file'] as  $requestUri => $count) {
             $matches = [];
             // note this is just an example to look for few of many possible suspicoius patterns ..             
             preg_match_all($pattern, $requestUri, $matches); 
             if (count($matches) >= 1 && isset($matches[0][0])) { 
                 $match =  trim($matches[0][0]);
                 if ($match != '') {
                    self::addToReport('malicious', $requestUri) ;
                 }
             }
         }
         
         $pattern = "/(binlar)|(casper)|(cmswor)|(diavol)|(finder)|(finder)|(nutch)/i";
         foreach (self::$analysis['user_agent'] as  $userAgent => $count) {
             preg_match_all($pattern, $userAgent, $matches); 
             if (count($matches) >= 1 && isset($matches[0][0])) { 
                 $match =  trim($matches[0][0]);
                 if ($match != '') {
                    self::addToReport('malicious', $userAgent) ;
                 }
             }
         }    
    }
    
    /**
    Entry point that reads and process log file
    **/
    public static function process(string $logFile) {
       
        self::$analysis['total_logs'] = 0;
        $fh = fopen($logFile,'r');
               
        while (! feof($fh)) {
            // read each line and trim off leading/trailing whitespace
            if ($lineBuffer = trim(fgets($fh, 16384))) {
                self::analyzeMatches($lineBuffer);                         
            }
            self::$analysis['total_logs']++;
        }
        
        fclose($fh);
        
        arsort(self::$analysis['file']); 
        arsort(self::$analysis['referer']);
        self::checkMaliciousAttack();   
        print_r(self::$analysis);   
    }

}

echo LogAnalyzer::process("access_log");
