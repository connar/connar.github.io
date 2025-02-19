+++
title = 'Projects'
layout = 'projects'
url = '/projects/'
summary = 'projects'
+++

A list of projects/tools that I have made along my journey of learning, either that be for a CTF or a real world scenario.

# Forensics
<table>
    <thead>
        <tr>
            <th></th>
            <th></th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
                <figure class="align-center ">
                    <img loading="lazy" src="/posts/projects/pcapanalyzer.png"/> 
                </figure>
            </td>
            <td>
                <strong>PcapAnalysis</strong> (<a href="https://github.com/connar/PcapAnalysis">GitHub</a>) <br> A script that is useful when analyzing malware traffic pcaps. It's goal is to find all HTTP and HTTPS hosts that a victim IP interacted with. Once it runs through the pcap file and collects all hosts which interacted with the victim ip, it makes request to VirusTotal in order to distinguish the malicious ones with the rest. It saves ...
            </td>
        </tr>
        <tr>
            <td>
                <figure class="align-center ">
                    <img loading="lazy" src="/posts/projects/pcapanon.png"/> 
                </figure>
            </td>
            <td>
                <strong>pcap_anonymizer</strong> (<a href="https://github.com/connar/pcap_anonymizer">GitHub</a>) <br> A script that anonymizes traffic of a given pcap file by randomizing IP and MAC addresses.
            </td>
        </tr>
    </tbody>
</table>


# Web Attacks
<table>
    <thead>
        <tr>
            <th></th>
            <th></th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
                <figure class="align-center ">
                    <img loading="lazy" src="/posts/projects/phpthumb.png"  /> 
                </figure>
            </td>
            <td>
                <strong>vulnerable_phpThumb</strong> (<a href="https://github.com/connar/vulnerable_phpThumb">GitHub</a>) <br> A script which scrapes the web using dorks to find domains that still use vulnerable versions of the phpThumb php script.
            </td>
        </tr>
    </tbody>
</table>

# Reversing tools
<table>
    <thead>
        <tr>
            <th></th>
            <th></th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
                <figure class="align-center ">
                    <img loading="lazy" src="https://upload.wikimedia.org/wikipedia/commons/thumb/7/7d/Microsoft_.NET_logo.svg/1024px-Microsoft_.NET_logo.svg.png" /> 
                </figure>
            </td>
            <td>
                <strong>DotNetParser</strong> (<a href="https://github.com/connar/DotNetParser">GitHub</a>) <br> A script that is used to quickly parse a .NET assembly to read its methods and instructions. It's just a quick way to parse and decompile raw bytecode to IL and read the instructions, instead of loading it to a decompiler like DnSpy, ILSpy etc.
            </td>
        </tr>
        <tr>
            <td>
                <figure class="align-center ">
                    <img loading="lazy" src="https://image-optimizer.cyberriskalliance.com/unsafe/768x0/https://files.scmagazine.com/wp-content/uploads/2023/06/BatCloak-e1686584681720.jpg" />
                </figure>
            </td>
            <td>
                <strong>Jlaive-Deobfuscator</strong> (<a href="https://github.com/connar/Jlaive-Deobfuscator">GitHub</a>) <br> A script that deobfuscates and reconstructs all parts used in the Jlaive obfuscation process, including the final decrypted executable.
            </td>
        </tr>
    </tbody>
</table>

# Obfuscation scripts
<table>
    <thead>
        <tr>
            <th></th>
            <th></th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
                <figure class="align-center ">
                    <img loading="lazy" src="/posts/projects/forcoding.png" />
                </figure>
            </td>
            <td>
                <strong>forcoding-Obfuscator</strong> (<a href="https://github.com/connar/forcoding-Obfuscator">GitHub</a>) <br> A script used for forcode-obfuscating cmd commands.
            </td>
        </tr>
    </tbody>
</table> 

# Automation tools / Scrapers
<table>
    <thead>
        <tr>
            <th></th>
            <th></th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>
                <figure class="align-center ">
                    <img loading="lazy" src="/posts/projects/pararius.png" />
                </figure>
            </td>
            <td>
                <strong>pscrapy</strong> (<a href="https://github.com/connar/Pararius_scraper">GitHub</a>) <br> A script used for scraping the Pararius website, find and submit forms for new properties - also bypassing cloudflares anti-bot protection.
            </td>
        </tr>
        <tr>
            <td>
                <figure class="align-center ">
                    <img loading="lazy" src="/posts/projects/infodisclosure.jpg" />
                </figure>
            </td>
            <td>
                <strong>info-disclosure</strong> (<a href="https://github.com/connar/info-disclosure">GitHub</a>) <br> A script that automates the process of Information disclosure files of a target website.
            </td>
        </tr>
        <tr>
            <td>
                <figure class="align-center ">
                    <img loading="lazy" src="/posts/projects/vulnparameters.png" />
                </figure>
            </td>
            <td>
                <strong>vuln-parameters</strong> (<a href="https://github.com/connar/vuln-parameters">GitHub</a>) <br> A script that automates the process of finding possibly vulnerable parameters of a target website.
            </td>
        </tr>
    </tbody>
</table> 