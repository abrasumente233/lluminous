import { writable } from 'svelte/store';
import { persisted } from './localstorage.js';

export const controller = writable(null);

export const params = persisted('params', {
	temperature: 0.3,
	min_p: 0,
  top_p: 1,
  top_k: 0,
  repetition_penalty: 1.0,
  presence_penalty: 0.0,
  frequency_penalty: 0.0,
	maxTokens: 0,
	messagesContextLimit: 0,
});

export const config = persisted('config', {
	explicitToolView: false,
});

export const openaiAPIKey = persisted('openaiAPIKey', '');
export const openrouterAPIKey = persisted('openrouterkey', '');
export const anthropicAPIKey = persisted('anthropicAPIKey', '');
export const groqAPIKey = persisted('groqAPIKey', '');
export const mistralAPIKey = persisted('mistralAPIKey', '');
export const fireworksAPIKey = persisted('fireworksAPIKey', '');
export const replicateAPIKey = persisted('replicateAPIKey', '');

export const remoteServer = persisted('remoteServer', { address: '', password: '' });
export const toolSchema = persisted('toolSchemaGroups', []);
