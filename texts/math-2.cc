// GH 12 wrong greek ERR_SCRIPTS with subscripts
#include <cmath>

int main()
{
   double εₙ₊₁, εₙ, εₙ₋₁, β₁, β₂, β₃, Δtₙ, k;
   const auto Δtₙ₊₁ = std::pow(εₙ₊₁, β₁/k) * std::pow(εₙ, β₂/k) * std::pow(εₙ₋₁, β₃/k) * Δtₙ; 
   return 0;
}
