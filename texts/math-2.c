#include <math.h>

int main()
{
   double εₙ₊₁, εₙ, εₙ₋₁, β₁, β₂, β₃, Δtₙ, k;
   const double Δtₙ₊₁ = pow(εₙ₊₁, β₁/k) * pow(εₙ, β₂/k) * pow(εₙ₋₁, β₃/k) * Δtₙ; 
   return 0;
}
