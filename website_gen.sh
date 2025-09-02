#!/bin/bash
rm -r website_folder
mkdir website_folder

curl -L -o website_folder/favicon.png "https://picsum.photos/64"

# number of images (you can pass as argument, e.g. ./script.sh 5)
n=${1:-3}

cat << EOF > website_folder/index.html
<!DOCTYPE html>
<html>
<head>
<title>Test Page</title>
</head>
<body>
EOF

for i in $(seq 1 $n); do
  curl -L -o website_folder/image$i.png "https://picsum.photos/400"
  echo "<img src=\"image$i.png\">" >> website_folder/index.html
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
