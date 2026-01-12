/**
 * Simple structured logger
 * Provides consistent logging format with timestamps
 */

const LOG_LEVELS = {
	DEBUG: 'DEBUG',
	INFO: 'INFO',
	WARN: 'WARN',
	ERROR: 'ERROR',
};

/**
 * Format a log message with timestamp and level
 * @param {string} level - Log level (DEBUG, INFO, WARN, ERROR)
 * @param {string} message - Main log message
 * @param {Object} context - Optional context object to include in log
 * @returns {string} Formatted log message
 */
function formatLog(level, message, context = {}) {
	const timestamp = new Date().toISOString();
	const contextStr = Object.keys(context).length > 0 ? ` ${JSON.stringify(context)}` : '';
	return `[${timestamp}] [${level}] ${message}${contextStr}`;
}

/**
 * Log a debug message
 * @param {string} message - Log message
 * @param {Object} context - Optional context data
 */
function debug(message, context = {}) {
	console.log(formatLog(LOG_LEVELS.DEBUG, message, context));
}

/**
 * Log an info message
 * @param {string} message - Log message
 * @param {Object} context - Optional context data
 */
function info(message, context = {}) {
	console.log(formatLog(LOG_LEVELS.INFO, message, context));
}

/**
 * Log a warning message
 * @param {string} message - Log message
 * @param {Object} context - Optional context data
 */
function warn(message, context = {}) {
	console.warn(formatLog(LOG_LEVELS.WARN, message, context));
}

/**
 * Log an error message
 * @param {string} message - Log message
 * @param {Object} context - Optional context data (can include error object)
 */
function error(message, context = {}) {
	console.error(formatLog(LOG_LEVELS.ERROR, message, context));
}

export default {
	debug,
	info,
	warn,
	error,
};
