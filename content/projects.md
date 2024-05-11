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
                    <img loading="lazy" src="https://www.cloudbric.com/wp-content/uploads/2023/10/IP-reputation-service-lookup-e1512437681827-1.png"/> 
                </figure>
            </td>
            <td>
                <strong>PcapAnalysis</strong> (<a href="https://github.com/connar/PcapAnalysis">GitHub</a>) <br> A script that is useful when analyzing malware traffic pcaps. It's goal is to find all HTTP and HTTPS hosts that a victim IP interacted with. Once it runs through the pcap file and collects all hosts which interacted with the victim ip, it makes request to VirusTotal in order to distinguish the malicious ones with the rest. It saves ...
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