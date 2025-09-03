#!/bin/bash
rm -r website_folder
mkdir website_folder


# number of images (you can pass as argument, e.g. ./script.sh 5)
n=${1:-3}
# number of bytes to keep for each image (optional second parameter)
truncate_bytes=${2:-0}

img_side=640

if [ "$truncate_bytes" -gt 0 ]; then
    curl -L -o website_folder/favicon.jpg "https://picsum.photos/$img_side"
    convert website_folder/favicon.jpg -interlace JPEG website_folder/favicon.jpg
    head -c $truncate_bytes website_folder/favicon.jpg > website_folder/tempfavicon.jpg
    mv website_folder/tempfavicon.jpg website_folder/favicon.jpg
else
    curl -L -o website_folder/favicon.jpg "https://picsum.photos/64"
fi


cat << EOF > website_folder/index.html
<!DOCTYPE html>
<html>
<head>
<title>Test Page</title>
<link rel="icon" type="image/jpeg" href="favicon.jpg">
<style>
body { display: flex; flex-wrap: wrap; }
img {width: 25%; padding: 2px; box-sizing: border-box;}
</style>
</head>
<body>
EOF

for i in $(seq 1 $n); do
    curl -L -o website_folder/image$i.jpg "https://picsum.photos/$img_side"
    if [ "$truncate_bytes" -gt 0 ]; then
        convert website_folder/image$i.jpg -interlace JPEG website_folder/image$i.jpg
        head -c $truncate_bytes website_folder/image$i.jpg > website_folder/temp$i.jpg
        mv website_folder/temp$i.jpg website_folder/image$i.jpg
    fi
    echo "<img src=\"image$i.jpg\">" >> website_folder/index.html
done

cat << EOF >> website_folder/index.html

<script>
let loadedCount = 0;
const totalImages = $n;
const startTime = performance.getEntriesByType('navigation')[0].fetchStart;

document.querySelectorAll('img').forEach(img => {
    img.onload = img.onerror = () => {
        loadedCount++;
        if (loadedCount === totalImages) {
            const endTime = performance.now() + performance.timeOrigin;
            const totalTime = endTime - startTime;
            console.log(\`\${totalTime.toFixed(2)}ms\`);
            
            // Check QUIC usage
            const resources = performance.getEntriesByType('resource');
            const imgResources = resources.filter(r => r.initiatorType === 'img');
            const quicCount = imgResources.filter(r => r.nextHopProtocol?.includes('quic') || r.nextHopProtocol?.includes('h3')).length;
            console.log(\`QUIC requests: \${quicCount}/\${totalImages}\`);
        }
    };
});
</script>
</body>
</html>
EOF
