export type DateOrder = 'day-first' | 'month-first';

export type TimeCycle = '24h' | '12h';

function twoDigit(value: number) {
  return value.toString().padStart(2, '0');
}

export function formatLocalDateTime(date: Date, dateOrder: DateOrder, timeCycle: TimeCycle) {
  const day = twoDigit(date.getDate());
  const month = twoDigit(date.getMonth() + 1);
  const year = date.getFullYear();
  const datePart = dateOrder === 'day-first' ? `${day}/${month}/${year}` : `${month}/${day}/${year}`;
  const hours = date.getHours();
  const minutes = twoDigit(date.getMinutes());
  const seconds = twoDigit(date.getSeconds());

  if (timeCycle === '12h') {
    const period = hours >= 12 ? 'PM' : 'AM';
    const displayHours = twoDigit(hours % 12 || 12);
    return `${datePart} ${displayHours}:${minutes}:${seconds} ${period}`;
  }

  return `${datePart} ${twoDigit(hours)}:${minutes}:${seconds}`;
}

export function parseLocalDateTime(value: string, dateOrder: DateOrder, timeCycle: TimeCycle) {
  const trimmedValue = value.trim();
  const match =
    timeCycle === '12h'
      ? trimmedValue.match(/^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)$/i)
      : trimmedValue.match(/^(\d{2})\/(\d{2})\/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})$/);

  if (!match) {
    return null;
  }

  const firstPart = Number(match[1]);
  const secondPart = Number(match[2]);
  const year = Number(match[3]);
  let hours = Number(match[4]);
  const minutes = Number(match[5]);
  const seconds = Number(match[6]);
  const day = dateOrder === 'day-first' ? firstPart : secondPart;
  const month = dateOrder === 'day-first' ? secondPart : firstPart;

  if (timeCycle === '12h') {
    if (hours < 1 || hours > 12) {
      return null;
    }

    const period = match[7].toUpperCase();
    hours = period === 'PM' ? (hours % 12) + 12 : hours % 12;
  }

  const date = new Date(year, month - 1, day, hours, minutes, seconds);
  const isValid =
    date.getFullYear() === year &&
    date.getMonth() === month - 1 &&
    date.getDate() === day &&
    date.getHours() === hours &&
    date.getMinutes() === minutes &&
    date.getSeconds() === seconds;

  return isValid ? date : null;
}
