"""Some utility functions to do some basic statistics calculations."""

import decimal


def poisson_cdf(actual, mean):
    """Return p(draw <= actual) when drawing from a poisson distribution.

    That is, we return the probability that we see actual or anything
    smaller in a random measurement of a variable with a poisson
    distribution with mean mean.

    Arguments:
       mean: a Decimal or a float.
    """
    if actual < 0:
        return decimal.Decimal(0)

    if isinstance(mean, float):
        # We use Decimal so that long periods and high numbers of
        # reports work -- a mean of 746 or higher would cause a zero
        # to propagate and make us report a probability of 0 even
        # if the actual probability was almost 1.
        mean = decimal.Decimal(mean)

    cum_prob = decimal.Decimal(0)

    p = (-mean).exp()
    cum_prob += p
    for i in xrange(actual):
        # We calculate the probability of each lesser value
        # individually, and sum as we go.
        p *= mean
        p /= i + 1
        cum_prob += p

    return float(cum_prob)


def count_is_elevated_probability(historical_count, historical_time_range,
                                  recent_count, recent_time_range):
    """Give the probability recent_count is elevated over the norm.

    That is, if we historically have seen N errors over S seconds, and
    then recently we saw N' errors over S' seconds, we'd like to know
    if the recent error rate is higher than the historical average.
    We assume that errors come in over a poisson distribution, so we
    can easily calculate the likelihood N' and N are actually the
    same.

    Arguments:
       historical_count: the number of errors seen in 'the past'.
       historical_time_range: how long we were measuring errors
           in 'the past'.  The units don't matter, though they
           should be the same as for recent_time_range.  They
           don't even need to be a time-unit; for instance they
           could be the number of http requests, if you consider
           every http request to be another clock 'tick'.
       recent_count: the number of errors seen in 'the present'.
       recent_time_range: how long we've been measuring errors
           in 'the present'.

    Returns:
       A pair: the expected number of errors we would have seen this period,
          and the probability that the number of errors we actually saw
          is actually higher than the expected number, both as floats.
    """
    if recent_count == 0:     # poisson_cdf isn't defined for -1.
        return (0.0, 0.0)
    if historical_time_range == 0:
        mean = 0.0
    else:
        mean = ((historical_count * 1.0 / historical_time_range) *
                recent_time_range)
    return (mean, poisson_cdf(recent_count - 1, mean))
