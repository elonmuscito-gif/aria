import { createHash } from 'crypto';

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

function hashPair(left: string, right: string): string {
  const [a, b] = left <= right ? [left, right] : [right, left];
  return sha256(`${a}:${b}`);
}

export interface MerkleTree {
  root: string;
  leaves: string[];
  layers: string[][];
}

export interface MerkleProof {
  leaf: string;
  leafIndex: number;
  siblings: Array<{ hash: string; position: 'left' | 'right' }>;
  root: string;
}

export function buildMerkleTree(leaves: string[]): MerkleTree {
  if (leaves.length === 0) {
    const empty = sha256('aria:empty');
    return { root: empty, leaves: [], layers: [[empty]] };
  }

  const hashedLeaves = leaves.map(l => sha256(l));

  const layers: string[][] = [hashedLeaves];
  let currentLayer = hashedLeaves;

  while (currentLayer.length > 1) {
    const nextLayer: string[] = [];

    for (let i = 0; i < currentLayer.length; i += 2) {
      const left = currentLayer[i]!;
      const right = currentLayer[i + 1] ?? left;
      nextLayer.push(hashPair(left, right));
    }

    layers.push(nextLayer);
    currentLayer = nextLayer;
  }

  return {
    root: currentLayer[0]!,
    leaves: hashedLeaves,
    layers
  };
}

export function generateProof(
  tree: MerkleTree,
  leafIndex: number
): MerkleProof | null {
  if (leafIndex < 0 || leafIndex >= tree.leaves.length) {
    return null;
  }

  const siblings: MerkleProof['siblings'] = [];
  let currentIndex = leafIndex;

  for (let i = 0; i < tree.layers.length - 1; i++) {
    const layer = tree.layers[i]!;
    const isRightNode = currentIndex % 2 === 1;
    const siblingIndex = isRightNode
      ? currentIndex - 1
      : currentIndex + 1;

    if (siblingIndex < layer.length) {
      siblings.push({
        hash: layer[siblingIndex]!,
        position: isRightNode ? 'left' : 'right'
      });
    }

    currentIndex = Math.floor(currentIndex / 2);
  }

  return {
    leaf: tree.leaves[leafIndex]!,
    leafIndex,
    siblings,
    root: tree.root
  };
}

export function verifyProof(proof: MerkleProof): boolean {
  let currentHash = proof.leaf;

  for (const sibling of proof.siblings) {
    if (sibling.position === 'left') {
      currentHash = hashPair(sibling.hash, currentHash);
    } else {
      currentHash = hashPair(currentHash, sibling.hash);
    }
  }

  return currentHash === proof.root;
}
