rule AlienSpy
{
	meta:
        author = "Kevin Breen"
        ref = "http://malwareconfig.com/stats/AlienSpy"
        maltype = "Remote Access Trojan"
        filetype = "jar"

	strings:
		$PK = "PK"
		$MF = "META-INF/MANIFEST.MF"

		$a1 = "a.txt"
		$a2 = "b.txt"
		$a3 = "Main.class"

		$b1 = "ID"
		$b2 = "Main.class"
		$b3 = "plugins/Server.class"

		$c1 = "resource/password.txt"
		$c2 = "resource/server.dll"

		$d1 = "java/stubcito.opp"
		$d2 = "java/textito.isn"

		$e1 = "java/textito.text"
		$e2 = "java/resources.xsx"

		$f1 = "config/config.perl"
		$f2 = "main/Start.class"


	condition:
        $PK at 0 and $MF and
        (all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*) or all of ($e*) or all of ($f*))
}
