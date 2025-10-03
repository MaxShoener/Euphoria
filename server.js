// Get engine choice from env variable, default to scramjet
const ENGINE = process.env.ENGINE || 'scramjet';

let engine;

try {
    if (ENGINE === 'scramjet') {
        console.log('Using Scramjet engine...');
        engine = require('scramjet');
    } else if (ENGINE === 'uv') {
        console.log('Using UV engine...');
        engine = require('uv');
    } else {
        throw new Error(`Unknown ENGINE value: ${ENGINE}`);
    }
} catch (err) {
    console.error('Failed to load engine:', err.message);
    process.exit(1);
}

// Example usage (replace with your actual logic)
async function main() {
    console.log(`Engine "${ENGINE}" is ready to use!`);

    // Example: create a simple stream or run engine-specific code
    if (ENGINE === 'scramjet') {
        // Example Scramjet usage
        const { DataStream } = engine;
        const ds = new DataStream([1,2,3,4,5]);
        ds.map(x => x * 2).each(x => console.log('Scramjet output:', x));
    } else if (ENGINE === 'uv') {
        // Example UV usage (replace with actual UV logic)
        console.log('UV engine loaded. Ready to process streams...');
    }
}

main();