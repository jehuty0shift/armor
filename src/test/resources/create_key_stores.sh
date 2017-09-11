rm -f Armor*.jks
rm -f armor*.pem

keytool -keystore ArmorKS.jks -genkey -v -validity 7200 -keyalg RSA -keypass changeit -storepass changeit -alias armor -dname "CN=localhost, OU=Armor, O=Test, L=Test, C=DE"
keytool -keystore ArmorFailKS.jks -genkey -v -validity 7200 -keyalg RSA -keypass changeit -storepass changeit -alias armorfail -dname "CN=localhost, OU=Armorfail, O=Test, L=Test, C=DE"

keytool -keystore ArmorKS.jks -selfcert -v -alias armor -storepass changeit
keytool -keystore ArmorFailKS.jks -selfcert -v -alias armorfail -storepass changeit

keytool -keystore ArmorKS.jks -export -v -keypass changeit -storepass changeit -rfc -alias armor -file armor.pem
keytool -keystore ArmorFailKS.jks -export -v -keypass changeit -storepass changeit -rfc -alias armorfail -file armorfail.pem

keytool -keystore ArmorTS.jks -import -noprompt  -v -keypass changeit -storepass changeit -alias armor -file armor.pem