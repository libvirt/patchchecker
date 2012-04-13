<?xml version="1.0"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  exclude-result-prefixes="xsl exsl"
  version="1.0">


  <xsl:output
    method="html"
    encoding="UTF-8"
    indent="yes"/>

  <xsl:template match="/">
<html>
  <head>
    <title>Pending patches needing review</title>
  </head>
  <body>
    <h1>Pending patches needing review</h1>

    <p> This is a list of <xsl:value-of select="/lagging/@count"/> patches
        pending review for the last 90 days on the project list.</p>
    <ul>
    <xsl:apply-templates select="/lagging/lag"/>
    </ul>
  </body>
</html>
  </xsl:template>

  <xsl:template match="lag">
    <li>Patch from <xsl:value-of select="@author"/>,
        sent <xsl:value-of select="@days"/> days ago:<br/>
        <a href="{url}"><xsl:value-of select="subject"/></a></li>
  </xsl:template>
</xsl:stylesheet>
