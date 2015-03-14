rule AlienSpy
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2015/03"
		ref = "http://malwareconfig.com/stats/AlienSpy"
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a1 = "Main.classPK"
		$a2 = "MANIFEST.MFPK"
		$a3 = "plugins/Server.classPK"
		$a4 = "META-INF/MANIFEST.MF"
        $a5 = "ID"
        
        $b1 = "config.xml"
        $b2 = "options/PK"
        $b3 = "plugins/PK"
        $b4 = "util/PK"
        $b5 = "util/OSHelper/PK"
        $b6 = "Start.class"
        $b7 = "AlienSpy"
	condition:
        all of ($a*) or all of ($b*)
}
